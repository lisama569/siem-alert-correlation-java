package com.github.lisama569.siemalertcorrelationjava.engine.alert;

import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertAction;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertCommand;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertState;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AuditEntry;
import com.github.lisama569.siemalertcorrelationjava.model.alert.CommandResult;
import com.github.lisama569.siemalertcorrelationjava.model.alert.TransitionFailure;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.FireOutcome;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 告警领域服务：由检测命中幂等创建告警，并执行生命周期跃迁。
 *
 * <p>并发正确性：
 * <ul>
 *   <li>每个 alertId 一把独立锁（{@link ConcurrentHashMap#compute} 原子替换），
 *       不同告警互不阻塞，同一告警的确认/抑制/关闭串行化；</li>
 *   <li>每次合法跃迁 version+1；命令可携带 expectedVersion 做乐观并发校验；</li>
 *   <li>因此并发操作不会丢失状态或错误覆盖。</li>
 * </ul>
 * 非法跃迁被拒绝并返回可区分的 {@link TransitionFailure}，同时写入审计链。
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    /** 合法状态跃迁矩阵（确定性、可解释）。 */
    private static final Map<AlertState, Map<AlertAction, AlertState>> TRANSITIONS = Map.of(
            AlertState.OPEN, Map.of(
                    AlertAction.ACKNOWLEDGE, AlertState.ACKNOWLEDGED,
                    AlertAction.SUPPRESS, AlertState.SUPPRESSED,
                    AlertAction.CLOSE, AlertState.CLOSED),
            AlertState.ACKNOWLEDGED, Map.of(
                    AlertAction.SUPPRESS, AlertState.SUPPRESSED,
                    AlertAction.CLOSE, AlertState.CLOSED),
            AlertState.SUPPRESSED, Map.of(
                    AlertAction.REOPEN, AlertState.OPEN,
                    AlertAction.CLOSE, AlertState.CLOSED),
            AlertState.CLOSED, Map.of(
                    AlertAction.REOPEN, AlertState.OPEN));

    private final Clock clock;
    private final Enricher enricher;
    private final Map<String, Alert> alerts = new ConcurrentHashMap<>();
    private final Map<String, String> fingerprintToAlertId = new ConcurrentHashMap<>();

    public AlertService(Clock clock, Enricher enricher) {
        this.clock = clock;
        this.enricher = enricher;
    }

    /** 按指纹幂等创建告警：同一指纹（同一规则条件）全局只产生一个告警。 */
    public Alert createIfAbsent(FireOutcome fire, RuleContext ctx) {
        String existingId = fingerprintToAlertId.get(fire.fingerprint());
        if (existingId != null) {
            return alerts.get(existingId);
        }
        String alertId = "ALERT-" + sha256Short(fire.fingerprint());
        // compute 保证同指纹并发创建只有一个胜出
        Alert created = alerts.compute(alertId, (id, current) -> {
            if (current != null) {
                return current;
            }
            long now = clock.millis();
            List<SecurityEvent> events = List.copyOf(fire.contributingEvents());
            long first = events.stream().mapToLong(SecurityEvent::eventTime).min().orElse(now);
            long last = events.stream().mapToLong(SecurityEvent::eventTime).max().orElse(now);
            AuditEntry birth = new AuditEntry(0, now, null, null, AlertState.OPEN,
                    "system", "规则命中自动创建: " + ctx.ruleId() + ":" + ctx.ruleVersion(),
                    true, null, "fingerprint=" + fire.fingerprint(), 0L, 1L);
            Alert alert = new Alert(id, fire.fingerprint(), ctx.ruleId(), ctx.ruleVersion(),
                    fire.correlationKey(), AlertState.OPEN, 1L, now, now, first, last,
                    ctx.severity(), events.size(), events, Map.of(), new ArrayList<>(List.of(birth)));
            Map<String, String> enrichment = enricher.enrich(alert);
            return new Alert(id, alert.fingerprint(), alert.ruleId(), alert.ruleVersion(),
                    alert.correlationKey(), alert.state(), alert.version(), alert.createdAtMs(),
                    alert.updatedAtMs(), alert.firstEventTimeMs(), alert.lastEventTimeMs(),
                    alert.severity(), alert.eventCount(), alert.contributingEvents(),
                    enrichment, alert.auditTrail());
        });
        fingerprintToAlertId.putIfAbsent(fire.fingerprint(), created.alertId());
        log.info("告警幂等创建/获取 alertId={} fingerprint={} state=OPEN version=1",
                created.alertId(), fire.fingerprint());
        return created;
    }

    /** 执行处置命令；无论成功失败都返回当前快照与可区分原因。 */
    public CommandResult apply(AlertCommand command) {
        if (command == null || command.alertId() == null || command.action() == null) {
            return CommandResult.fail(null, TransitionFailure.INVALID_PAYLOAD, "alertId/action 不能为空");
        }
        Alert current = alerts.get(command.alertId());
        if (current == null) {
            return CommandResult.fail(null, TransitionFailure.ALERT_NOT_FOUND, command.alertId());
        }
        // 每告警独立锁 + 原子替换，串行化同告警的并发处置
        Alert updated = alerts.compute(command.alertId(), (id, inside) ->
                inside == null ? current : transition(inside, command));
        AuditEntry last = updated.auditTrail().get(updated.auditTrail().size() - 1);
        if (last.accepted()) {
            log.info("告警跃迁成功 alertId={} {} -> {} by={} version={}",
                    updated.alertId(), last.fromState(), last.toState(), command.actor(), updated.version());
            return CommandResult.ok(updated);
        }
        return CommandResult.fail(updated, TransitionFailure.valueOfCode(last.rejectionCode()), last.detail());
    }

    private Alert transition(Alert alert, AlertCommand command) {
        long now = clock.millis();
        long seq = alert.auditTrail().size();

        // 1) 乐观版本校验
        if (command.expectedVersion() != null
                && command.expectedVersion() != alert.version()) {
            return reject(alert, seq, now, command, null, TransitionFailure.VERSION_CONFLICT,
                    "expectedVersion=" + command.expectedVersion() + " actualVersion=" + alert.version());
        }
        // 2) 同状态幂等：目标状态与当前状态相同（ACKNOWLEDGE->ACKNOWLEDGED 等显式矩阵外的自环）
        Map<AlertAction, AlertState> allowed = TRANSITIONS.get(alert.state());
        AlertState target = allowed.get(command.action());
        if (target == null) {
            // 区分：CLOSED 上的非 REOPEN 动作，与"已处于目标状态"
            if (alert.state() == AlertState.CLOSED && command.action() != AlertAction.REOPEN) {
                return reject(alert, seq, now, command, null,
                        TransitionFailure.ACTION_NOT_ALLOWED_ON_CLOSED,
                        "CLOSED 状态仅允许 REOPEN，收到动作 " + command.action());
            }
            if (leadsToSameState(alert.state(), command.action())) {
                return reject(alert, seq, now, command, alert.state(),
                        TransitionFailure.ALREADY_IN_STATE,
                        "告警已处于 " + alert.state() + "，动作 " + command.action() + " 无效");
            }
            return reject(alert, seq, now, command, null,
                    TransitionFailure.ILLEGAL_TRANSITION,
                    alert.state() + " 不允许动作 " + command.action());
        }
        // 3) 合法跃迁
        AuditEntry entry = new AuditEntry(seq, now, command.action(), alert.state(), target,
                nz(command.actor()), nz(command.reason()), true, null, null,
                alert.version(), alert.version() + 1);
        return alert.withTransition(target, entry);
    }

    private static boolean leadsToSameState(AlertState state, AlertAction action) {
        return (state == AlertState.ACKNOWLEDGED && action == AlertAction.ACKNOWLEDGE)
                || (state == AlertState.SUPPRESSED && action == AlertAction.SUPPRESS)
                || (state == AlertState.CLOSED && action == AlertAction.CLOSE);
    }

    private Alert reject(Alert alert, long seq, long now, AlertCommand command,
                         AlertState target, TransitionFailure failure, String detail) {
        AuditEntry entry = new AuditEntry(seq, now, command.action(), alert.state(),
                target == null ? alert.state() : target, nz(command.actor()), nz(command.reason()),
                false, failure.code(), detail, alert.version(), alert.version());
        log.info("告警跃迁被拒绝 alertId={} state={} action={} code={} detail={}",
                alert.alertId(), alert.state(), command.action(), failure.code(), detail);
        return alert.withRejectedAudit(entry);
    }

    public Optional<Alert> get(String alertId) {
        return Optional.ofNullable(alerts.get(alertId));
    }

    public List<Alert> list() {
        return List.copyOf(alerts.values());
    }

    public int size() {
        return alerts.size();
    }

    /** 测试辅助。 */
    public void reset() {
        alerts.clear();
        fingerprintToAlertId.clear();
    }

    private static String nz(String s) {
        return s == null || s.isBlank() ? "anonymous" : s.trim();
    }

    private static String sha256Short(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", digest[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    /** 创建告警所需的规则上下文。 */
    public record RuleContext(String ruleId, String ruleVersion, String ruleName,
                              String severity, long windowMs, long allowedLatenessMs) {
    }
}
