# 本地威胁检测与告警关联（SIEM Alert Correlation）

一套**完全本地可运行**的威胁检测与告警关联流程：用本地事件流模拟多来源安全日志，
在乱序、重复提交与并发处置下保证检测结论与告警状态**一致、确定、可复现、可解释**。
不依赖任何外部服务、数据库、真实凭据或不可访问资源（仅使用 Spring Boot 内嵌容器与 JDK）。

## 1. 模块与事件模型

包结构：

| 包 | 职责 |
|---|---|
| `model` | 归一化事件模型与接入结果（`SecurityEvent` / `IngestResult` / `RejectReason`） |
| `ingest` | 原始事件 `RawEvent`、归一化校验（来源白名单/时间/网络地址）与幂等去重 `IngestionService` |
| `ingest.support` | 纯本地网络地址字面量（IPv4/IPv6）识别与校验 `NetworkAddresses` |
| `rule` | 检测规则定义与带历史版本的注册表 `RuleRegistry` |
| `detection` | 时间窗口关联检测引擎 `DetectionEngine` |
| `alert` | 告警实体、生命周期状态机与并发控制 `AlertService` |
| `pipeline` | 接入 → 检测 的编排 `EventPipeline`（HTTP 层与演示共用） |
| `config` | 本地纯内存组件装配 `LocalBeans`（规则、服务、引擎单例） |
| `web` | 本地 HTTP 入口（提交事件、查询/处置告警）与统一错误响应 |
| `simulator` | 本地事件流演示 `DemoRunner`（默认关闭） |

### 1.1 原始事件 RawEvent

各来源以字符串形式提交：

```
RawEvent(eventId, source, type, occurredAt, attributes)
```

`occurredAt` 必须是 ISO-8601（如 `2026-09-24T08:00:00Z`）；`attributes` 为字符串键值对，
规则通过其中的字段（如 `user`、`host`）分组。

### 1.2 归一化事件 SecurityEvent

```
SecurityEvent(eventId, source, EventType type, Instant occurredAt,
              Instant receivedAt, Map<String,String> attributes)
```

- `occurredAt`：事件实际发生时间（事件时间），窗口归属与乱序判定只看它；
- `receivedAt`：系统接收时间（接收时间），仅用于审计，不参与判定。

## 2. 接入语义：收紧校验、不静默丢弃、幂等去重

`IngestionService.ingest(raw)` 返回三态：

- `Accepted(event)`：校验通过并归一化；
- `Duplicate(eventId)`：该 `eventId` 已被接受过，直接返回，**不进入检测、不重复计数**。
  去重集合基于 `ConcurrentHashMap.newKeySet()`，`add` 是原子的先到先得，
  因此并发重复提交也只放行一次；
- `Rejected(reason, detail)`：字段缺失或语义非法，带可区分原因（见 §5.1），
  记录不会被静默丢弃，**也不会占用 eventId 去重名额**（即同 ID 改正后仍可被接受）。

### 2.1 收紧后的接入校验

在原有"非空 + 类型合法 + ISO-8601"基础上，本轮新增三道收紧，并保持**校验顺序固定**——
与字段在记录中的排列无关，同一条记录每次提交拿到的拒绝原因一定相同：

1. `eventId` 非空（`MISSING_EVENT_ID`）；
2. `source` 非空（`MISSING_SOURCE`），且**必须在受认可来源白名单内**，
   否则按 `UNKNOWN_SOURCE` 单独拒绝，未见过的来源不会被当成正常事件留下。
   默认白名单：`auth-gateway`、`firewall`、`ids`、`edr`、`proxy`
   （大小写敏感、去除首尾空白后精确匹配；可通过构造器 `new IngestionService(clock, allowedSources)` 注入）；
3. `type` 非空（`MISSING_TYPE`）且在 `EventType` 枚举内（`UNKNOWN_EVENT_TYPE`）；
4. `occurredAt` 非空（`MISSING_OCCURRED_AT`）、为合法 ISO-8601（`INVALID_TIMESTAMP`），
   且**不得晚于当前时间**（依据可注入的 `Clock`），来自未来的时间戳按
   `FUTURE_TIMESTAMP` 单独拒绝，不会被默默放过；
5. 属性中**表示网络地址的字段**，其值必须是合法 IPv4/IPv6 字面量，否则按
   `INVALID_IP_ADDRESS` 单独拒绝。字段名按字典序逐个检查、只报第一个非法字段，
   保证结果稳定；该校验为纯本地解析，不做任何 DNS 查询、不接受域名。

网络地址字段的识别是确定性的：把字段名按驼峰边界与 `_`/`-` 切成小写 token，
只要出现 `ip` / `ipv4` / `ipv6` 之一即命中。因此 `srcIp`、`dst_ip`、
`clientIpAddress`、`IPV6` 会被校验，而 `zip`、`description`、`host` 不会被误判。
合法示例：`192.168.0.1`、`0.0.0.0`、`2001:db8::1`、`::1`、`::ffff:192.0.2.1`；
非法示例：`256.0.0.1`、`01.2.3.4`（前导零）、`1.2.3`（段数不足）、
`example.com`（域名）、`2001::1::8`（多个压缩段）。

以上全部通过后才进行幂等去重，因此任何被拒绝的记录都不会进入检测、计数或去重集合。

## 3. 窗口、乱序与迟到处理语义

规则定义 `RuleDefinition(ruleId, version, description, eventType, groupByField,
windowSize, allowedLateness, threshold)`。

### 3.1 滚动时间窗口

- 窗口按 `windowSize` **对齐到纪元**：`windowStart = floor(occurredAt / windowSize)`，
  左闭右开 `[windowStart, windowStart+windowSize)`；
- 同一规则按 `groupByField`（如账号）分组独立计数；
- 窗口内同一 `EventType` 事件计数 `>= threshold` 即满足规则。

### 3.2 乱序（out-of-order）

- 窗口归属**只取决于 `occurredAt`**，与到达顺序无关。乱序到达的事件会被插入缓冲区后
  按事件时间排序再计数，因此正序与乱序喂入同一事件流，最终窗口计数、告警 ID、
  关联到的事件集合完全相同（见 `DetectionEngineTest#outOfOrderArrivalYieldsSameConclusion`）。

### 3.3 迟到与水位线（late event & watermark）

- 每条规则维护：`watermark = 已见最大 occurredAt - allowedLateness`；
- `occurredAt >= watermark` 的迟到事件：容忍，正常进入窗口参与关联；
- `occurredAt < watermark` 的事件：**超出容忍范围**，明确丢弃，不参与计数，
  并在检测说明中输出一条 `DROP_LATE` 记录（含事件 ID、事件时间、当前水位线、规则版本），
  判定依据可解释；
- 注意：`allowedLateness` 需与窗口大小配合。乱序跨度大于容忍度时，较早事件会被丢弃，
  这是确定性行为而非错误。

### 3.4 告警去重与规则变更复现

- 告警 ID 是确定性的：`ruleId-v版本-分组值-窗口起点epochMillis`；
- 引擎对每个 `(ruleId, ruleVersion, 分组, 窗口)` 只触发一次，
  整批事件重复评估也不会产生第二条告警（外加 `AlertService.register` 的幂等兜底）；
- 规则在 `RuleRegistry` 中按版本永久保留，新版本号必须**严格递增**（否则抛异常）。
  规则变更后：
  - 新版本下的判定使用新版本状态空间，不会让旧条件"补触发"告警；
  - 用某个历史版本注册一张全新注册表/引擎重放同一事件流，即可**逐字节复现历史判定**
    （见 `DetectionEngineTest#ruleChangeKeepsHistoryReproducible`）。

## 4. 告警富化与生命周期

### 4.1 富化

告警创建时写入不可变暗字段（规则、版本、关联事件 ID 列表）与富化字段：
分组值、窗口起止、事件计数、首末事件时间、资产重要度（`hostCriticality`，缺省 `UNKNOWN`），
严重级别按计数是否达到阈值 2 倍取 `HIGH` / `MEDIUM`。

### 4.2 状态流转

合法跃迁表（非法跃迁被拒绝并区分原因，见 §5.2）：

```
OPEN          -> ACKNOWLEDGED | SUPPRESSED | CLOSED
ACKNOWLEDGED  -> SUPPRESSED   | CLOSED
SUPPRESSED    -> CLOSED
CLOSED        -> （终态，任何跃迁均拒绝：ALREADY_TERMINAL）
```

### 4.3 并发一致性

- 每次跃迁在**该告警对象的监视器锁**内完成 check-then-act，
  并发的确认/抑制/关闭串行化，不会丢失更新或把 `CLOSED` 覆盖回其他状态；
- 每次成功跃迁都使版本号 `version + 1`，并向处置历史追加一条
  `Disposition(时间, 操作人, 动作, from, to, note)`；被拒绝的跃迁不写入历史；
- 对外只暴露 `snapshot()` 深拷贝，读取不受并发修改影响；
- 可选乐观锁：调用方携带 `expectedVersion`，版本不符时返回 `VERSION_CONFLICT`。

## 5. 错误分类

### 5.1 事件接入 `RejectReason`

校验按 §2.1 的固定顺序执行；一条记录同时踩中多个问题时，始终返回顺序最靠前的那个原因。

| 原因 | 含义 |
|---|---|
| `MISSING_EVENT_ID` | eventId 为空 |
| `MISSING_SOURCE` | source 为空 |
| `UNKNOWN_SOURCE` | source 非空，但不在受认可来源白名单中（本轮新增） |
| `MISSING_TYPE` | type 为空 |
| `UNKNOWN_EVENT_TYPE` | type 不在 `EventType` 枚举中（语义非法） |
| `MISSING_OCCURRED_AT` | occurredAt 为空 |
| `INVALID_TIMESTAMP` | occurredAt 不是合法 ISO-8601 |
| `FUTURE_TIMESTAMP` | occurredAt 晚于当前时间（来自未来，本轮新增） |
| `INVALID_IP_ADDRESS` | 网络地址字段的值不是合法 IPv4/IPv6 字面量（本轮新增） |
| `INVALID_FIELD_VALUE` | 预留的通用属性非法原因（当前未使用，保留以兼容既有枚举序号） |

### 5.2 告警跃迁 `TransitionError`

| 原因 | 含义 |
|---|---|
| `ALERT_NOT_FOUND` | 告警 ID 不存在 |
| `ILLEGAL_TRANSITION` | 当前状态不允许跃迁到目标状态（且非终态场景） |
| `ALREADY_TERMINAL` | 告警已是 `CLOSED` 终态 |
| `VERSION_CONFLICT` | 乐观锁版本不匹配 |

## 6. 本地 HTTP 入口

启动后内嵌 Tomcat **仅监听 `127.0.0.1:8080`**（见 `application.properties` 的
`server.address=127.0.0.1`），全部处理在内存完成，不接外部服务、不需要真实凭据。
运营同学无需改代码即可：手工灌事件、按编号查告警及其处置历史、对告警发起处置。

### 6.1 提交原始事件

单条 `POST /api/events`，请求体即原始事件字段：

```bash
curl -s -X POST http://127.0.0.1:8080/api/events \
  -H 'Content-Type: application/json' \
  -d '{"eventId":"e1","source":"firewall","type":"LOGIN_FAILED",
       "occurredAt":"2026-09-27T08:00:00Z",
       "attributes":{"user":"alice","srcIp":"10.0.0.5"}}'
```

| HTTP | 响应 `outcome` | 含义 |
|---|---|---|
| `200` | `ACCEPTED` | 正常受理，已进入检测 |
| `409` | `DUPLICATE` | 重复提交，未重复计数/告警 |
| `422` | `REJECTED` | 被拒绝，响应 `reason` 给出 §5.1 的具体原因（如 `UNKNOWN_SOURCE` / `FUTURE_TIMESTAMP` / `INVALID_IP_ADDRESS`） |
| `400` | `MALFORMED_REQUEST` | 请求体缺失或不是合法 JSON |

批量 `POST /api/events/batch`，请求体 `{"events":[ ... ]}`。**HTTP 固定返回 `200`**，
逐条结果在 `items[]` 中各自带 `outcome`/`reason`，并给出聚合计数
`total/accepted/duplicate/rejected`，便于一次灌一批后逐条核对；空批次返回 `400`。

`GET /api/events/allowed-sources` 返回当前受认可来源集合。

### 6.2 按编号查告警（含处置历史）

```bash
curl -s http://127.0.0.1:8080/api/alerts/brute-force-login-v1-alice-1790236800000
```

- `200`：返回告警只读视图，含富化字段、关联 `eventIds` 与完整 `history`（处置链）；
- `404` + `{"error":"ALERT_NOT_FOUND"}`：按编号查不到。
- `GET /api/alerts` 可列出全部告警。

告警编号沿用既有确定性规则：`ruleId-v版本-分组值-窗口起点epochMillis`。

### 6.3 对告警发起处置

动作写在 URL 路径段：`acknowledge`（或 `ack`）/ `suppress` / `close`。

```bash
curl -s -X POST http://127.0.0.1:8080/api/alerts/<alertId>/acknowledge \
  -H 'Content-Type: application/json' \
  -d '{"operator":"ops-1","note":"已确认","expectedVersion":0}'
```

`operator` 缺省为 `anonymous`，`note` 可空，`expectedVersion` 可选（乐观锁）。

| HTTP | 响应 | 含义 |
|---|---|---|
| `200` | `{"outcome":"APPLIED","alert":...}` | 处置成功，返回处置后快照（version 已 +1） |
| `404` | `ALERT_NOT_FOUND` | 告警不存在 |
| `409` | `ILLEGAL_TRANSITION` | 当前状态不允许该跃迁（且非终态） |
| `409` | `ALREADY_TERMINAL` | 告警已是 CLOSED 终态，不会被改回 |
| `409` | `VERSION_CONFLICT` | 携带的 `expectedVersion` 与当前版本不符 |
| `400` | `INVALID_ACTION` | URL 中的动作名非法 |

这样"正常受理 / 重复提交 / 被拒绝（且能区分是哪一种）/ 查不到 / 状态冲突"
五类情况在状态码与机读字段上都可区分。

## 7. 本地验证方法

前置：JDK 21+、Maven 3.9+（无需联网下载以外的任何外部服务）。

### 7.1 单元 / 集成测试

```bash
mvn test
```

覆盖（共 25 个用例）：

- `NetworkAddressesTest`：网络地址字段名识别（含不误判 `zip`/`host`）、
  合法 IPv4/IPv6 放行、各类非法字面量拒绝；
- `IngestionServiceTest`：归一化、全部可区分拒绝原因（含本轮新增
  `UNKNOWN_SOURCE` / `FUTURE_TIMESTAMP` / `INVALID_IP_ADDRESS`）、
  **固定校验顺序稳定性**（同一记录多次提交原因一致）、被拒记录不占去重名额、
  重复提交幂等；
- `DetectionEngineTest`：乱序结论一致、超容忍迟到事件被丢弃且有原因、
  重复提交不重复告警、规则变更后历史可复现；
- `AlertServiceTest`：合法生命周期与可追溯历史、非法跃迁/终态/版本冲突的区分拒绝、
  16 线程并发确认+关闭下的状态不变量（关闭只成功一次、历史链连续、版本号一致）；
- `HttpApiTest`：HTTP 全栈区分 受理(200)/重复(409)/各类拒绝(422，reason 可区分)/
  请求非法(400)/查不到(404)/各类状态冲突(409：ILLEGAL_TRANSITION、
  ALREADY_TERMINAL、VERSION_CONFLICT)，以及批量逐条 outcome；
- `BatchConcurrencyTest`：见 §7.2 的批量与并发验收。

测试日志打印每个用例的**输入、关键判定依据（EVAL / DROP_LATE 等）与最终状态**，
可在控制台或 `target/surefire-reports/` 查看。

### 7.2 批量与并发验收（规模与通过标准）

`BatchConcurrencyTest` 固化了本地可复现的规模，并用 `@RepeatedTest(3)`
**用同一批输入重复跑 3 遍**，结论每次都必须一致：

| 场景 | 规模 | 并发 |
|---|---|---|
| 批量提交 | 一次性 **1000** 条（100 组 × 10，阈值 10） | 单批顺序 |
| 并发接入 | **6400** 条唯一事件（100 组 × 64，阈值 64） | **64** 线程同一屏障后并发提交 |
| 并发重放 | 同样 6400 条原样再灌一次 | 64 线程并发 |
| 并发处置 | **100** 条告警，每条 16 个处置（8 确认 + 8 关闭） | **16** 线程/告警 |

通过标准（确定性，与线程调度无关；所有事件用同一固定事件时间、1h 窗口、
10min 迟到容忍，因此到达顺序不改变水位线与窗口归属）：

- 并发接入：`accepted=6400, duplicate=0, rejected=0`，`acceptedCount()` 恰为 6400，
  不丢不重；产生恰好 **100** 条告警，每条关联**恰好 64** 个事件；
- 并发重放：`accepted=0, duplicate=6400, rejected=0`，`acceptedCount` 不再增长，
  告警仍为 100 条（重复提交不重复计数、不重复告警）；
- 并发处置：每条告警**关闭只成功一次**、最终必为 `CLOSED`、
  `version == history.size()`、处置历史是连续合法跃迁链，终态不会被并发改回；
- 批量：1000 条全部受理、100 条告警各关联 10 个事件。

复现方式：

```bash
mvn -Dtest=BatchConcurrencyTest test     # 含 3 轮重复
# 或整段回归：
mvn test
```

### 7.3 端到端本地演示

```bash
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Ddemo.enabled=true"
```

`DemoRunner` 会构造一条包含乱序、重复、超容忍迟到、非法类型、缺字段、未认可来源、
未来时间戳、非法网络地址的本地事件流，依次演示 接入归一化（含各类可区分拒绝）→
窗口检测（含 EVAL/DROP_LATE/ALERT 判定说明）→ 告警确认/关闭/终态拒绝，并打印
告警处置历史。不带该参数启动时演示不运行。

需要真正通过 HTTP 手工操作时，去掉 `demo.enabled` 正常 `mvn spring-boot:run`
启动后按 §6 的 curl 示例操作即可（仅监听 127.0.0.1）。

## 8. 相对既有行为的兼容范围

本轮在不推倒既有实现的前提下扩展，以下规则与数据形态**保持不变**：

- **告警编号规则不变**：仍是 `ruleId-v版本-分组值-窗口起点epochMillis`，
  窗口纪元对齐口径、左闭右开窗、分组字段、阈值/严重度富化逻辑均未改动；
- **窗口与水位线判定口径不变**：`windowSize` 对齐、`watermark = 最大事件时间 -
  allowedLateness`、超容忍迟到丢弃并记 `DROP_LATE` 的行为保持一致；
- **处置历史与状态机不变**：合法跃迁表、终态拒绝原因、`version` 递增、
  `Disposition` 结构与乐观锁语义均保留；既有 `AlertService` / `DetectionEngine`
  / `RuleRegistry` 的公开方法签名未变；
- **接入结果三态不变**：仍是 `Accepted` / `Duplicate` / `Rejected`，
  幂等去重机制（原子集合先到先得）不变。

有意收紧（属于本轮要求的行为变更）：

- 接入新增三道校验，过去能混入的**未认可来源、未来时间戳、非法网络地址**现在会被
  单独拒绝；因此依赖"任意来源字符串都能接入"的旧调用方需要改用白名单内来源
  （默认含 `auth-gateway/firewall/ids/edr/proxy`，也可构造器注入自定义集合）；
- `RejectReason` 为**追加式**扩展（新增枚举常量，保留全部既有常量），
  对既有枚举名与序号兼容；接入层现按 §2.1 的固定顺序给出拒绝原因。
- 构建新增显式 `java.version=21`（此前 Spring Boot 父 POM 默认按 17 编译测试，
  主代码未用 21 语法才未暴露），与项目要求的 JDK 21 一致。

## 9. 设计取舍小结

- 判定确定性：事件时间窗口 + 纪元对齐 + 确定性告警 ID，相同输入必得相同结论；
- 可解释：拒绝原因（含来源/时间/网络地址分类）、水位线丢弃记录、每步 EVAL 计数、
  处置历史全部留痕；
- 并发安全：接入去重用原子集合，检测引擎按调用串行（`synchronized`），
  告警跃迁按实体加锁并提供乐观版本号；6400 事件 / 64 线程 / 100 告警 × 16 处置
  的规模下计数、告警与状态不重不丢（见 §7.2）；
- 纯内存实现、无外部依赖、HTTP 仅绑回环地址，适合本地验证与教学演示；
  生产化需替换存储与时钟来源（`Clock` 已可注入以便测试）。
