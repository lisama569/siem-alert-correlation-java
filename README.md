# 本地威胁检测与告警关联（SIEM Alert Correlation）

一个**完全本地可运行**、无外部服务/真实凭据依赖的 Spring Boot 应用：用本地事件流模拟多来源安全日志，
在**乱序、重复、并发**条件下给出确定、可复现、可解释的检测结论与告警状态。

- Java 21 · Spring Boot 3.4 · 纯内存状态 · JUnit 5
- 运行：`mvn spring-boot:run`（启动后自动执行一次端到端演示并打印全过程）
- 测试：`mvn test`

---

## 1. 总体流程

```
RawEvent(弱类型原始事件)
   │  EventNormalizer 归一化 / 校验
   ├─ 非法或字段缺失 → IngestionOutcome(拒绝, RejectionReason 错误码)   （绝不静默丢弃）
   ▼
IngestionService 确定性去重（eventId 幂等）
   ├─ 重复提交 → duplicate=true，不计数、不进入检测
   ▼
CorrelationEngine（每个规则版本独立状态）
   │  事件时间水位线 → 乱序/迟到判定 → 会话窗口关联 → 指纹去重
   ├─ 触发 FireOutcome(fired)
   ▼
AlertService.createIfAbsent（按指纹幂等建告警）→ Enricher 本地富化
   ▼
告警生命周期：OPEN → ACKNOWLEDGED → SUPPRESSED / CLOSED …（每告警加锁 + 版本号 + 审计链）
```

---

## 2. 事件模型

### 2.1 原始事件 `RawEvent`

| 字段 | 含义 |
|---|---|
| source | 来源，归一化为枚举：`HOST_EDR / NETWORK_FIREWALL / AUTH_SERVICE / WEB_GATEWAY`（大小写、连字符容错） |
| type | 类型：`LOGIN_FAILED / LOGIN_SUCCESS / PRIVILEGE_USE / MALWARE_DETECTED / FIREWALL_BLOCK / ACCESS_DENIED / WEB_ATTACK_SIGNATURE` |
| eventTime | ISO-8601 时间（如 `2026-09-24T10:00:00Z`），内部统一为 epoch 毫秒 |
| rawId | 来源侧事件 ID；缺失时由内容 SHA-256 指纹兜底 |
| user / srcIp / dstIp / host / attributes | 实体字段与扩展属性 |

### 2.2 归一化事件 `SecurityEvent`

在原始字段基础上增加：

- `eventId`（确定性主键）= `来源 + "#" + rawId`；无 rawId 时 = `来源 + "#" + 内容指纹`。
  因此**跨来源不会撞 ID，同源同 ID 即为同一事件**。
- `ingestTime`：接入处理时间（注入的 `Clock`，测试中可固定）。

### 2.3 归一化拒绝原因（不静默丢弃，原因可区分）

校验顺序固定为 **来源 → 类型 → 时间 → IP**，一条记录一次返回一个确定原因：

| 错误码 | 枚举 | 含义 |
|---|---|---|
| E101 | MISSING_SOURCE | 来源缺失 |
| E102 | UNKNOWN_SOURCE | 来源无法识别 |
| E103 | MISSING_TYPE | 类型缺失 |
| E104 | UNKNOWN_TYPE | 类型无法识别 |
| E105 | MISSING_EVENT_TIME | 事件时间缺失 |
| E106 | INVALID_EVENT_TIME | 时间不是合法 ISO-8601 |
| E107 | EVENT_TIME_IN_FUTURE | 时间超过"现在 + 60s"未来容忍 |
| E108 | INVALID_SOURCE_IP | 源 IP 语义非法（缺失合法、出现即须合法 IPv4/IPv6） |
| E109 | INVALID_DEST_IP | 目标 IP 语义非法 |

被拒绝事件**不进入去重集合**，修正后可用同一 rawId 重新提交。

### 2.4 去重语义

- 首次接入：`accepted=true, duplicate=false`，唯一计数 +1；
- 再次提交相同 `eventId`：`accepted=true, duplicate=true`，**不重复计数、不进入检测、不产生重复告警**；
- 基于并发集合的 `addIfAbsent` 语义，多线程并发提交同一事件也恰好计数一次。

---

## 3. 检测规则、时间窗口与乱序处理

### 3.1 规则模型 `RuleDefinition`（不可变、带版本）

```
ruleId + version + name
eventType        命中的事件类型
correlateBy      关联键字段：SRC_IP / USER / HOST（字段缺失回退为 "NONE"）
threshold        同键会话内命中数达到该值即触发
windowMs         窗口长度，用于水位线与事件归档
allowedLatenessMs 容忍迟到范围
maxGapMs         会话间隔：相邻命中事件时间差超过它即切为新会话
severity         MEDIUM / HIGH / CRITICAL
```

- 规则以 `ruleId:version` 为键**不可变存储**：同版本重复注册内容必须一致，否则拒绝（错误码 R301）。
- 同一 `ruleId` 下版本字符串最大者为**生效版本**；旧版本永久保留，可随时按版本重放历史。
- 内置规则见 `config/BuiltInRules`，其中 `R-BRUTE-FORCE` 同时注册了 **v1（阈值 5）/ v2（阈值 3）** 用于演示规则变更。

### 3.2 水位线与乱序/迟到（确定性）

引擎使用**纯事件时间水位线**（实时处理与历史重放判定完全一致）：

```
watermark = max(已观测事件时间) − allowedLatenessMs     （单调不减）
```

| 事件相对水位线 | 结论 | 处理 |
|---|---|---|
| `eventTime ≥ watermark` | `ON_TIME` | 正常判定 |
| `watermark − lateness ≤ eventTime < watermark` | `ACCEPTED_WITHIN_LATENESS` | 仍参与判定 |
| `eventTime < watermark − lateness` | `REJECTED_TOO_LATE` | **确定性丢弃**，结果中可解释 |

- 事件按事件时间排序后做**会话（session）聚类**，所以容忍范围内无论事件以什么顺序到达，
  最终触发结论与指纹一致（有专项测试：按序 `t0,t5,t10` 与乱序 `t0,t10,t4` 结论相同）。
- 早于 `watermark − windowMs` 的事件被归档，不再影响后续判定。

### 3.3 触发与"同一条件不重复告警"

- 同关联键、同类型事件按 `maxGapMs` 切会话；会话内事件数达到 `threshold` 触发一次。
- 触发**指纹** = `ruleKey | correlationKey | 会话锚点事件 eventId`（锚点 = 会话内事件时间最小、并列取 eventId 最小者）。
- 两层去重保证不重复触发：
  1. **锚点指纹记忆**：同锚点会话再次达标只返回 `suppressedDuplicate`；
  2. **已参与触发事件记忆**：容忍范围内迟到事件把已触发会话向前扩张、导致锚点前移时，
     该会话只被抑制，绝不二次告警。
- 规则版本是指纹命名空间的一部分：升级到新版本后，**新条件按新版本触发，旧告警不会被同一条件重复触发**；
  以旧版本重放仍得到当年的判定。

### 3.4 历史复现 `RuleReplayer`

`replay(ruleVersion, 事件序列)` 每次使用全新临时引擎与纯事件时间时钟：

- 结论只取决于「规则版本 + 事件序列（含到达顺序）」，**重复重放指纹完全一致**；
- 不写实时状态、不建告警，对线上零副作用。
- 报告 `ReplayReport` 给出：触发数、重复抑制数、过迟丢弃数、逐条 `FireOutcome` 与指纹集合。

---

## 4. 告警富化与生命周期

### 4.1 富化 `Enricher`（纯本地）

仅使用进程内信息：规则元数据、事件数量/时间跨度、内置 IP 情报表
（如 `198.51.100.23 → KNOWN_BAD_IP:malware-c2`）、重点关注账户表。**无任何网络调用。**

### 4.2 状态与合法跃迁

```
                 ACKNOWLEDGE                SUPPRESS
   OPEN ───────────────────────▶ ACKNOWLEDGED ──────────▶ SUPPRESSED
     │  SUPPRESS                    │ CLOSE                 │ CLOSE
     └──────────────▶ SUPPRESSED ◀──┘                       ▼
                       │  CLOSE                           CLOSED
                       └──────────────▶ CLOSED ◀────────────┘
   CLOSED ── REOPEN ──▶ OPEN        SUPPRESSED ── REOPEN ──▶ OPEN
```

| 当前状态 | 允许动作 |
|---|---|
| OPEN | ACKNOWLEDGE, SUPPRESS, CLOSE |
| ACKNOWLEDGED | SUPPRESS, CLOSE |
| SUPPRESSED | REOPEN, CLOSE |
| CLOSED | REOPEN |

### 4.3 非法跃迁的拒绝原因（带错误码）

| 错误码 | 枚举 | 触发情形 |
|---|---|---|
| A201 | ILLEGAL_TRANSITION | 当前状态不允许该动作（如 OPEN 上 REOPEN） |
| A202 | ALREADY_IN_STATE | 目标状态与当前状态相同（如 ACKNOWLEDGED 上再 ACKNOWLEDGE） |
| A203 | ACTION_NOT_ALLOWED_ON_CLOSED | CLOSED 上使用非 REOPEN 动作 |
| A204 | VERSION_CONFLICT | 携带的 `expectedVersion` 与当前版本不符（乐观锁） |
| A205 | ALERT_NOT_FOUND | 告警不存在 |
| A206 | INVALID_PAYLOAD | 请求参数/动作非法 |

### 4.4 并发正确性与可追溯

- **每个 alertId 独立加锁**（`ConcurrentHashMap.compute` 原子替换），同一告警的确认/抑制/关闭串行化，
  不同告警互不阻塞；配合 `version` 乐观锁，并发操作**不丢失状态、不错误覆盖**。
- 每次合法跃迁生成不可变新快照：`state` 更新、`version + 1`；被拒绝命令状态不变，但同样写入审计。
- `auditTrail` 记录：序号、时间、动作、from/to 状态、操作者、原因、是否接受、拒绝码、from/to 版本。
  成功跃迁审计中 `toVersion = fromVersion + 1` 连续无重复，处置全程可追溯。
- 告警按指纹幂等创建：同一规则条件全局只有一个告警（并发创建也只有一个胜出）。

---

## 5. HTTP 接口（本地）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/events` | 提交原始事件；成功返回 eventId/各规则判定/告警 ID；拒绝返回 422 + E1xx 错误码 |
| GET  | `/api/alerts` | 告警列表（含状态、版本、富化、审计链） |
| GET  | `/api/alerts/{id}` | 单告警详情 |
| POST | `/api/alerts/{id}/actions` | 处置：body `{action, actor, reason, expectedVersion?}`；非法跃迁 422/A2xx，版本冲突 409/A204，不存在 404/A205 |
| GET  | `/api/rules` | 生效规则版本列表 |
| POST | `/api/rules` | 注册规则（版本不可变，冲突 422/R301） |

示例：

```bash
mvn spring-boot:run &
# 提交事件
curl -s -X POST localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "source":"AUTH_SERVICE","type":"LOGIN_FAILED",
  "eventTime":"2026-09-24T10:00:00Z","rawId":"curl-1",
  "user":"alice","srcIp":"10.0.0.11","dstIp":"10.0.0.1"}'
# 确认告警
curl -s -X POST localhost:8080/api/alerts/<ID>/actions -H 'Content-Type: application/json' \
  -d '{"action":"ACKNOWLEDGE","actor":"analyst-1","reason":"开始调查"}'
```

---

## 6. 本地验证方法

### 6.1 一键运行 + 自动演示

```bash
mvn spring-boot:run        # 或 mvn -DskipTests package && java -jar target/*.jar
```

启动时 `DemoRunner`（`app.demo.enabled=true`，测试中自动关闭）消费 `LocalEventStream`，
该数据集相对运行时刻动态生成时间戳，刻意包含：正常事件、容忍内乱序、超容忍迟到事件、
重复提交、5 类非法记录。日志按 `[输入] / [判定] / [触发] / [告警] / [拒绝] / [最终状态]`
打印输入、关键判定依据（水位线、迟到结论、指纹、会话事件数）与最终状态，随后演示：

- 对暴力破解告警**并发**提交 ACKNOWLEDGE/SUPPRESS/CLOSE，展示最终状态与完整审计链；
- 用规则 **v1 / v2 分别重放**同一历史序列，展示阈值差异、指纹一致与可复现性。

### 6.2 单元测试（含并发与乱序，日志打印输入/依据/状态）

```bash
mvn test
```

| 测试类 | 覆盖点 |
|---|---|
| `NormalizerTest` | 成功归一化、确定性 ID、9 种拒绝原因逐一可区分 |
| `IngestionDedupTest` | 重复提交计数一次、拒绝后修正可重提、16 线程并发幂等 |
| `OutOfOrderCorrelationTest` | 乱序与按序结论/指纹一致、超容忍确定丢弃、同会话不重复触发、独立会话、迟到扩张不二次告警 |
| `RuleReplayTest` | v1/v2 阈值差异、重放可复现、规则版本不可变、版本指纹命名空间隔离 |
| `AlertLifecycleTest` | 全量合法跃迁、A201/A202/A203 区分、A204 版本冲突、幂等创建、A205 |
| `ConcurrentTransitionTest` | 100 个并发处置：成功数=版本增量、版本连续无重复、审计无缺口；32 线程并发建同一告警幂等 |
| `EndToEndPipelineTest` | Spring 上下文 + 本地事件流端到端结论、MockMvc 覆盖 HTTP 成功/422/409/404/400 |

测试日志使用 logger `SIEM-TEST`，统一打印 `[输入]/[判定依据]/[结果]/[最终状态]`。

---

## 7. 关键包结构

```
common/util        IpValidator
model/event        RawEvent / SecurityEvent / EventSource / EventType / RejectionReason / IngestionOutcome
model/rule         RuleDefinition / CorrelationField / LateDecision / FireOutcome / ReplayReport
model/alert        Alert / AlertState / AlertAction / AlertCommand / AuditEntry / TransitionFailure / CommandResult
engine/ingest      EventNormalizer / IngestionService
engine/correlation RuleRegistry / CorrelationEngine / RuleReplayer
engine/alert       Enricher / AlertService
pipeline           DetectionPipeline
stream             LocalEventStream（确定性模拟数据）
demo               DemoScenario / DemoRunner
web                EventController / AlertController / RuleController / GlobalExceptionHandler
config             AppConfig（可注入 Clock） / BuiltInRules
```

## 8. 设计要点小结：一致性从何而来

1. **确定身份**：eventId 由来源+rawId/内容指纹决定；告警指纹由规则版本+关联键+会话锚点决定。
2. **确定时间**：纯事件时间水位线 + 固定的会话聚类与触发规则，使乱序在容忍内收敛到同一结论。
3. **不可变版本**：规则与告警均为不可变快照/定义，历史可按版本重放，结论可复现。
4. **并发控制**：接入用 addIfAbsent；引擎按规则状态加锁；告警按 ID 加锁 + 版本号；审计只追加。
5. **失败显式化**：归一化与状态跃迁的每类失败都有稳定错误码，拒绝也留痕，绝不静默吞掉。
