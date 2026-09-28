# 本地威胁检测与告警关联（SIEM Alert Correlation）

一套**完全本地可运行**的威胁检测与告警关联流程：用本地事件流模拟多来源安全日志，
在乱序、重复提交与并发处置下保证检测结论与告警状态**一致、确定、可复现、可解释**。
不依赖任何外部服务、数据库、真实凭据或不可访问资源（仅使用 Spring Boot 内嵌容器与 JDK）。

## 1. 模块与事件模型

包结构：

| 包 | 职责 |
|---|---|
| `model` | 归一化事件模型与接入结果（`SecurityEvent` / `IngestResult` / `RejectReason`） |
| `ingest` | 原始事件 `RawEvent`、归一化校验（来源白名单/未来时间/网络地址）与幂等去重 `IngestionService` |
| `rule` | 检测规则定义与带历史版本的注册表 `RuleRegistry` |
| `detection` | 时间窗口关联检测引擎 `DetectionEngine` |
| `alert` | 告警实体、生命周期状态机与并发控制 `AlertService` |
| `api` | 本地 HTTP 入口：事件提交、告警查询、确认/抑制/关闭 |
| `simulator` | 本地事件流演示 `DemoRunner`（默认关闭） |

`PipelineConfig` 把接入、检测、告警服务装配为 Spring Bean（纯内存），
HTTP 入口与命令行演示复用同一套服务语义；默认注册 `brute-force-login` v1 规则。

### 1.1 原始事件 RawEvent

各来源以字符串形式提交（HTTP 接口直接接收 JSON）：

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

### 2.1 固定校验顺序

`IngestionService.ingest(raw)` 按下列**固定顺序**逐项校验，
因此同一条记录无论提交多少次、是否并发，拿到的拒绝原因都相同：

1. `eventId` 为空 → `MISSING_EVENT_ID`
2. `source` 为空 → `MISSING_SOURCE`
3. `source` 不在认可来源集合 → `UNKNOWN_SOURCE`
4. `type` 为空 → `MISSING_TYPE`
5. `type` 不在 `EventType` 枚举内 → `UNKNOWN_EVENT_TYPE`
6. `occurredAt` 为空 → `MISSING_OCCURRED_AT`
7. `occurredAt` 不是合法 ISO-8601 → `INVALID_TIMESTAMP`
8. `occurredAt` 晚于当前接收时间（未来事件）→ `FUTURE_TIMESTAMP`
9. 网络地址字段（命名风格无关，见下）的值不是合法 IPv4/IPv6
   → `INVALID_IP_ADDRESS`；一条记录有多个地址字段非法时，提示按**字段名升序**
   把所有非法字段逐一点名，同一条记录的拒绝原因与提示每次完全一致

- **来源白名单**：默认认可 `auth-gateway`、`firewall`、`ids`、`edr`、`dns-proxy`
  （`IngestionService.DEFAULT_ALLOWED_SOURCES`），可通过构造参数覆盖；未被认可的来源
  以独立原因 `UNKNOWN_SOURCE` 拒绝，不会被当成正常事件留下。
- **未来时间**：判定基准是可注入的 `Clock`（默认系统 UTC 时钟），
  `occurredAt == now` 合法，严格晚于 `now` 才拒绝；便于用固定时钟做确定性测试。
- **网络地址字段识别（命名风格无关）**：由 `IpFieldMatcher` 负责。属性名先做
  **风格归一化**——转小写并去掉下划线 `_`、连字符 `-`、点 `.` 与空白——再与固定的
  **规范地址字段名集合**（语义前缀 `"" / src / dst / source / destination /
  client / server / remote / local / orig / resp` × 后缀 `ip / ipaddress` 的全部组合）
  做精确匹配。因此 `srcIp`、`src_ip`、`SRC_IP`、`src-ip`、`source.ip`、
  `SourceIPAddress`、`clientIp`、`server_ip_address` 等写法都会被识别为地址字段。
  采用"归一后精确命中集合"而不是"包含 ip 子串"，因此 `user`、`host`、`hostname`、
  `script`、`ipHint` 等**不表示地址**的普通属性绝不做地址校验，不会被误伤。
- **地址字面量校验**：纯本地解析（不做 DNS 查询）。IPv4 为点分十进制、每段 0-255；
  IPv6 支持标准 8 组、`::` 压缩（至多一个、至少压缩一组）以及位于地址**最末位**的
  内嵌 IPv4（如 `::ffff:192.0.2.1`、`2001:db8::192.0.2.1`）；字段缺省（不存在）
  与此前一致不做校验，字段存在但值为空仍按非法地址拒绝（口径未变）。
- **拒绝结果确定性**：地址字段在校验阶段（进入去重集合之前）按字段名升序检查，
  所有非法字段一次性写入同一条提示，与 `attributes` 的遍历/插入顺序无关。
  因此同一条记录无论重复提交、并发提交，还是服务重启（内存状态清空）后再交一次，
  `RejectReason` 与 `detail` 都逐字一致；被拒记录不进入计数，也不会进入检测或告警。

### 2.2 三态结果

- `Accepted(event)`：校验通过并归一化，随后进入检测；
- `Duplicate(eventId)`：该 `eventId` 已被接受过，直接返回，**不进入检测、不重复计数**。
  去重集合基于 `ConcurrentHashMap.newKeySet()`，`add` 是原子的先到先得，
  因此并发重复提交也只放行一次；
- `Rejected(reason, detail)`：按 §2.1 的顺序返回首个失败原因（见 §5.1），
  被拒记录不会进入去重集合，也不会被静默丢弃。

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
  按事件时间排序再计数，因此正序与乱序喂入同一事件流，最终窗口计数、告警 ID 一致；
  对同一事件集合，首达阈值的那 3 条事件按事件时间确定，故告警关联事件集合也相同
  （见 `DetectionEngineTest#outOfOrderArrivalYieldsSameConclusion`）。

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
`eventCount` 固化**首达阈值那一刻**的窗口计数（兼容口径，不因后续事件追加而改写）。

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

## 5. 本地 HTTP 接口

启动：`mvn spring-boot:run`（默认端口 8080；整条链路纯本地，无外部服务/真实凭据）。
所有响应均为 JSON；调用方按 **HTTP 状态码 + 响应体 result/error 字段** 区分结果。

### 5.1 提交单条事件 `POST /api/events`

请求体即一个 `RawEvent`：

```bash
curl -X POST http://localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "eventId":"e1","source":"auth-gateway","type":"LOGIN_FAILED",
  "occurredAt":"2026-09-24T08:00:00Z","attributes":{"user":"mallory","srcIp":"10.1.2.3"}
}'
```

| 情况 | HTTP 状态 | `result` | 说明 |
|---|---|---|---|
| 正常受理 | **201** | `ACCEPTED` | 已归一化并进入检测；`alertsCreated` 给出新触发告警 ID |
| 重复提交 | **200** | `DUPLICATE` | 幂等返回，不重复计数、不重复告警 |
| 校验拒绝 | **422** | `REJECTED` | `reason` 为 §6.1 中的具体拒绝原因，`detail` 可读 |

非法地址在任何命名风格下都会被拒绝（原因固定为 `INVALID_IP_ADDRESS`），可手工复现：

```bash
# 以下 src_ip / SRC-IP / source.ip 都会被识别为地址字段，值非法 -> 422
curl -i -X POST http://localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "eventId":"bad-1","source":"firewall","type":"NETWORK_CONNECTION",
  "occurredAt":"2026-09-24T08:00:00Z","attributes":{"src_ip":"999.1.1.1"}}'
# detail 形如：网络地址字段不是合法 IPv4/IPv6: src_ip=999.1.1.1, eventId=bad-1
```

### 5.2 批量提交 `POST /api/events/batch`

请求体是 `RawEvent` 数组。整体返回 **200**，逐条结果在 `items[]` 中区分
（同样三态 + 拒绝原因），汇总计数 `accepted / duplicates / rejected`，
`alertsCreated` 为本批新触发的告警。整批受理事件一次性进入检测，
窗口口径与逐条提交完全一致。

### 5.3 查询告警

- `GET /api/alerts`：列出全部告警；
- `GET /api/alerts/{alertId}`：返回告警与**完整处置历史** `history[]`；
  查不到时返回 **404** 且 `error = ALERT_NOT_FOUND`。

### 5.4 发起处置

- `POST /api/alerts/{alertId}/acknowledge`
- `POST /api/alerts/{alertId}/suppress`
- `POST /api/alerts/{alertId}/close`

请求体：`{"operator":"ops-1","note":"人工确认","expectedVersion":1}`
（`operator` 缺省为 `anonymous`；`note` 可空；`expectedVersion` 可选，用于乐观锁）。

| 情况 | HTTP 状态 | 响应体 |
|---|---|---|
| 处置成功 | **200** | `result=SUCCESS`，`alert` 为跃迁后快照（含新 `version` 与历史） |
| 告警不存在 | **404** | `error=ALERT_NOT_FOUND` |
| 当前状态不允许该跃迁 | **409** | `error=ILLEGAL_TRANSITION` |
| 告警已是 CLOSED 终态 | **409** | `error=ALREADY_TERMINAL` |
| 乐观锁版本不匹配 | **409** | `error=VERSION_CONFLICT`，detail 给出期望/实际版本 |

## 6. 错误分类

### 6.1 事件接入 `RejectReason`

| 原因 | 含义 |
|---|---|
| `MISSING_EVENT_ID` | eventId 为空 |
| `MISSING_SOURCE` | source 为空 |
| `UNKNOWN_SOURCE` | source 不在认可来源白名单 |
| `MISSING_TYPE` | type 为空 |
| `UNKNOWN_EVENT_TYPE` | type 不在 `EventType` 枚举中（语义非法） |
| `MISSING_OCCURRED_AT` | occurredAt 为空 |
| `INVALID_TIMESTAMP` | occurredAt 不是合法 ISO-8601 |
| `FUTURE_TIMESTAMP` | occurredAt 晚于当前接收时间（未来事件） |
| `INVALID_IP_ADDRESS` | 网络地址字段（命名风格无关识别，见 §2.1）不是合法 IPv4/IPv6；多个非法字段按字段名升序在 detail 中点名 |

### 6.2 告警跃迁 `TransitionError`

| 原因 | 含义 |
|---|---|
| `ALERT_NOT_FOUND` | 告警 ID 不存在 |
| `ILLEGAL_TRANSITION` | 当前状态不允许跃迁到目标状态（且非终态场景） |
| `ALREADY_TERMINAL` | 告警已是 `CLOSED` 终态 |
| `VERSION_CONFLICT` | 乐观锁版本不匹配 |

## 7. 本地验证方法

前置：JDK 21+、Maven 3.9+（无需联网下载以外的任何外部服务）。

### 7.1 单元测试

```bash
mvn test
```

共 28 个用例，全部为本地确定性测试：

- `IngestionServiceTest`（7）：归一化、**可区分拒绝原因**（含未知来源、
  未来时间、非法地址）、**固定校验顺序的确定性**、合法 IPv4/IPv6 放行、重复提交幂等；
- `IpAddressIngestionTest`（6）：地址收紧的专项覆盖——
  23 种命名风格键（驼峰/下划线/连字符/点/大小写、src/dst/source/destination/
  client/server/remote/local/orig/resp/ip）× 8 种非法值全部以 `INVALID_IP_ADDRESS`
  拒绝且提示点名字段；合法 IPv4/IPv6（含 `::` 压缩、最末位内嵌 IPv4）放行；
  `user/host/hostname/script/srcPort/ipHint` 等普通属性不被误伤；多字段非法时按
  字段名升序点名、与属性插入顺序无关；同一条记录重复 5 次、重建链路（模拟重启）3 次、
  16 线程并发提交，拒绝原因与提示逐字一致；批量混合 + 重提/重放 3 轮，
  被拒不计数不告警、合法事件 6 受理 / 6 幂等、告警恒为 1 条；
- `DetectionEngineTest`（4）：乱序结论一致、超容忍迟到事件被丢弃且有原因、
  重复提交不重复告警、规则变更后历史可复现（既有，不回归）；
- `AlertServiceTest`（4）：合法生命周期与可追溯历史、非法跃迁/终态/版本冲突的区分拒绝、
  16 线程并发确认+关闭下的状态不变量（既有，不回归）；
- `ApiControllerTest`（3）：HTTP 受理/重复/拒绝三类区分且拒绝原因可见；
  查询/确认/版本冲突/关闭/终态/查不到六类结果的状态码与响应体区分；批量混合输入汇总；
- `CapacityConcurrencyTest`（3）：批量、并发与幂等验收（规模与标准见 §7.3）。

```bash
mvn test -Dtest=IpAddressIngestionTest                    # 只跑地址收紧专项
for i in 1 2 3; do mvn test -Dtest=IpAddressIngestionTest; done  # 连跑 3 遍验证确定性
```

测试日志打印每个用例的**输入、关键判定依据（EVAL / DROP_LATE 等）与最终状态**，
可直接在控制台或 `target/surefire-reports/*-output.txt` 查看。

### 7.2 端到端本地演示

```bash
mvn spring-boot:run                                          # 启动 HTTP 服务
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Ddemo.enabled=true"  # 命令行演示
```

`DemoRunner` 会构造一条包含乱序、重复、超容忍迟到、非法类型、缺字段的本地事件流，
依次演示 接入归一化 → 窗口检测（含 EVAL/DROP_LATE/ALERT 判定说明）→
告警确认/关闭/终态拒绝，并打印告警处置历史。不带该参数启动时演示不运行。
HTTP 手工验证示例见 §5。

### 7.3 批量与并发验收规模、通过标准与复现方法

`CapacityConcurrencyTest` 固定以下本地可复现规模（接收时间固定为 2026-09-27，
全部事件时间在此之前，排除未来事件干扰）：

| 场景 | 规模 | 通过标准 |
|---|---|---|
| 单批提交 | **一批 2000 条**（200 账号 × 10 条同窗口失败） | 受理 2000；恰好 200 条告警；200 个分组都出现 `计数=10` 的 EVAL 记录；每条告警在阈值处固化 `eventCount=3`；**同一批输入重建链路重放 3 轮，告警编号集合逐轮完全一致** |
| 并发提交 | **16 线程 × 250 条 = 4000 条**（400 账号，打乱分片，每条受理后立即评估） | 线程受理总数与去重计数均为 4000（不丢、不重）；恰好 400 条告警，编号集合与 400 个预期分组完全相等；每条告警的 3 个关联事件都属于本组（不串组） |
| 并发重复提交 | 上述 4000 条再由 16 线程整体重提一遍 | 4000 条全部判为 `DUPLICATE`；去重计数仍 4000；告警仍 400 条 |
| 并发处置 | **16 线程同时关闭同一条告警** | 恰好 1 次成功、15 次 `ALREADY_TERMINAL`；最终 `CLOSED`、版本连续 `0→1`、历史恰好 1 条且 from/to 合法；已关闭告警不会被并发改回 |

复现方法：

```bash
mvn test -Dtest=CapacityConcurrencyTest        # 单遍
for i in 1 2 3; do mvn test -Dtest=CapacityConcurrencyTest; done   # 连跑 3 遍
```

实测连续多遍运行结论一致（4000 条并发提交在本机亚秒级完成）。
`AlertServiceTest#concurrentTransitionsAreConsistent` 另外覆盖 16 线程"确认+关闭"
混合竞争：关闭只成功一次、历史链连续、成功跃迁数 == 版本号 == 历史条数。

## 8. 兼容性说明

### 8.1 本轮（地址字段识别收紧）

- **保持兼容**：确定性告警编号规则、纪元对齐窗口与水位线口径、告警状态机与处置历史、
  乐观锁版本号语义、`Alert`/`SecurityEvent`/`RawEvent` 字段、多线程灌入与多线程处置下
  的计数不重不漏和状态/版本连续性均未改变；原有 22 个用例继续通过（仅把原因常量名
  `INVALID_FIELD_VALUE` 替换为更精确的 `INVALID_IP_ADDRESS`，拒绝语义与 HTTP 422
  状态码不变）。合法 IPv4/IPv6 照常放行，字段缺省/为空的处理口径与此前一致。
- **收紧（潜在不兼容）**：
  1. 地址字段识别从"5 个写死的驼峰名精确匹配"改为**命名风格无关的语义识别**
     （见 §2.1 `IpFieldMatcher`）。此前 `src_ip`、`SRC_IP`、`src-ip`、`source.ip`、
     `clientIpAddress` 等写法下的非法值会漏网进入检测，现在一律以
     `INVALID_IP_ADDRESS` 拒绝；
  2. 拒绝原因 `INVALID_FIELD_VALUE` 更名为专门的 `INVALID_IP_ADDRESS`，
     与其它拒绝原因可明确区分；一条记录多个地址字段非法时，detail 按字段名升序
     **点名全部非法字段**，结果与提交次数、并发、重启无关，完全可复现；
  3. 顺手修正 IPv6 字面量边界：内嵌 IPv4 只允许位于地址最末位
     （此前 `1.2.3.4::` 这类写法会被误判为合法）。
- **不误伤**：`user`、`host`、`hostname`、`script`、`srcPort`、`ipHint` 等
  普通属性不做地址校验（识别是"归一后精确命中规范名集合"，不做 `ip` 子串包含）。

### 8.2 上一轮（接入收紧 / HTTP / 批量并发）

- **保持兼容**：确定性告警编号规则、纪元对齐窗口口径、水位线迟到丢弃口径、
  告警状态机与处置历史格式、乐观锁版本号语义、`Alert`/`SecurityEvent`/
  `RawEvent` 字段与既有规则定义均未改变；原有 12 个用例不改动行为继续通过
  （`IngestionServiceTest` 中一处占位来源 `"s"` 替换为认可来源 `"firewall"`，
  所覆盖的拒绝语义不变）。
- **收紧（潜在不兼容）**：接入新增 3 类拒绝——来源必须在白名单内、
  `occurredAt` 不得晚于接收时刻、网络地址属性必须是合法地址；
  原先这些输入会被当作正常事件受理，现在返回 `UNKNOWN_SOURCE` /
  `FUTURE_TIMESTAMP` / `INVALID_IP_ADDRESS`。白名单可通过构造参数
  `new IngestionService(clock, allowedSources)` 调整。
- **新增**：本地 HTTP 接口（§5）、`PipelineConfig` Bean 装配、
  批量接入、以及对应自动化测试；均为新增面，不改变既有判定逻辑。

## 9. 设计取舍小结

- 判定确定性：事件时间窗口 + 纪元对齐 + 确定性告警 ID，相同输入必得相同结论；
- 可解释：拒绝原因（固定顺序）、水位线丢弃记录、每步 EVAL 计数、处置历史全部留痕；
- 并发安全：接入去重用原子集合，检测引擎按调用串行（`synchronized`），
  告警跃迁按实体加锁并提供乐观版本号；
- 纯内存实现、无外部依赖，适合本地验证与教学演示；生产化需替换存储与时钟来源
  （`Clock` 已可注入以便测试）。
