# 本地威胁检测与告警关联（SIEM Alert Correlation）

一套**完全本地可运行**的威胁检测与告警关联流程：用本地事件流模拟多来源安全日志，
在乱序、重复提交与并发处置下保证检测结论与告警状态**一致、确定、可复现、可解释**。
不依赖任何外部服务、数据库、真实凭据或不可访问资源（仅使用 Spring Boot 内嵌容器与 JDK）。

## 1. 模块与事件模型

包结构：

| 包 | 职责 |
|---|---|
| `model` | 归一化事件模型与接入结果（`SecurityEvent` / `IngestResult` / `RejectReason`） |
| `ingest` | 原始事件 `RawEvent`、归一化校验与幂等去重 `IngestionService` |
| `rule` | 检测规则定义与带历史版本的注册表 `RuleRegistry` |
| `detection` | 时间窗口关联检测引擎 `DetectionEngine` |
| `alert` | 告警实体、生命周期状态机与并发控制 `AlertService` |
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

## 2. 接入语义：不静默丢弃、幂等去重

`IngestionService.ingest(raw)` 返回三态：

- `Accepted(event)`：校验通过并归一化；
- `Duplicate(eventId)`：该 `eventId` 已被接受过，直接返回，**不进入检测、不重复计数**。
  去重集合基于 `ConcurrentHashMap.newKeySet()`，`add` 是原子的先到先得，
  因此并发重复提交也只放行一次；
- `Rejected(reason, detail)`：字段缺失或语义非法，带可区分原因（见 §5.1），
  记录不会被静默丢弃。

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

| 原因 | 含义 |
|---|---|
| `MISSING_EVENT_ID` | eventId 为空 |
| `MISSING_SOURCE` | source 为空 |
| `MISSING_TYPE` | type 为空 |
| `UNKNOWN_EVENT_TYPE` | type 不在 `EventType` 枚举中（语义非法） |
| `MISSING_OCCURRED_AT` | occurredAt 为空 |
| `INVALID_TIMESTAMP` | occurredAt 不是合法 ISO-8601 |

### 5.2 告警跃迁 `TransitionError`

| 原因 | 含义 |
|---|---|
| `ALERT_NOT_FOUND` | 告警 ID 不存在 |
| `ILLEGAL_TRANSITION` | 当前状态不允许跃迁到目标状态（且非终态场景） |
| `ALREADY_TERMINAL` | 告警已是 `CLOSED` 终态 |
| `VERSION_CONFLICT` | 乐观锁版本不匹配 |

## 6. 本地验证方法

前置：JDK 21+、Maven 3.9+（无需联网下载以外的任何外部服务）。

### 6.1 单元测试

```bash
mvn test
```

覆盖：

- `IngestionServiceTest`：归一化、6 类可区分拒绝原因、重复提交幂等；
- `DetectionEngineTest`：乱序结论一致、超容忍迟到事件被丢弃且有原因、
  重复提交不重复告警、规则变更后历史可复现；
- `AlertServiceTest`：合法生命周期与可追溯历史、非法跃迁/终态/版本冲突的区分拒绝、
  16 线程并发确认+关闭下的状态不变量（关闭只成功一次、历史链连续、版本号一致）。

测试日志打印每个用例的**输入、关键判定依据（EVAL / DROP_LATE 等）与最终状态**，
可直接在控制台或 `target/surefire-reports/*-output.txt` 查看。

### 6.2 端到端本地演示

```bash
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Ddemo.enabled=true"
```

`DemoRunner` 会构造一条包含乱序、重复、超容忍迟到、非法类型、缺字段的本地事件流，
依次演示 接入归一化 → 窗口检测（含 EVAL/DROP_LATE/ALERT 判定说明）→
告警确认/关闭/终态拒绝，并打印告警处置历史。不带该参数启动时演示不运行。

## 7. 设计取舍小结

- 判定确定性：事件时间窗口 + 纪元对齐 + 确定性告警 ID，相同输入必得相同结论；
- 可解释：拒绝原因、水位线丢弃记录、每步 EVAL 计数、处置历史全部留痕；
- 并发安全：接入去重用原子集合，检测引擎按调用串行（`synchronized`），
  告警跃迁按实体加锁并提供乐观版本号；
- 纯内存实现、无外部依赖，适合本地验证与教学演示；生产化需替换存储与时钟来源
  （`Clock` 已可注入以便测试）。
