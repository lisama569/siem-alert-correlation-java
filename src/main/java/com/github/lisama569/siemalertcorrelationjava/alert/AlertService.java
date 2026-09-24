package com.github.lisama569.siemalertcorrelationjava.alert;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 告警生命周期服务。
 *
 * <p>状态机（合法跃迁）：
 * <pre>
 *   OPEN         -> ACKNOWLEDGED | SUPPRESSED | CLOSED
 *   ACKNOWLEDGED -> SUPPRESSED   | CLOSED
 *   SUPPRESSED   -> CLOSED
 *   CLOSED       -> （终态，任何跃迁均拒绝，原因 ALREADY_TERMINAL）
 * </pre>
 *
 * <p>并发保证：对同一告警的跃迁在该告警对象的监视器上串行化，
 * check-then-act 不会交错，因此并发确认/抑制/关闭不会丢失或互相覆盖；
 * 后到的操作要么按新状态继续合法跃迁，要么以可区分原因被拒绝。
 * 调用方还可携带 expectedVersion 做乐观并发控制（VERSION_CONFLICT）。
 */
public class AlertService {

    private static final Map<AlertStatus, Set<AlertStatus>> LEGAL = new EnumMap<>(AlertStatus.class);

    static {
        LEGAL.put(AlertStatus.OPEN,
                EnumSet.of(AlertStatus.ACKNOWLEDGED, AlertStatus.SUPPRESSED, AlertStatus.CLOSED));
        LEGAL.put(AlertStatus.ACKNOWLEDGED,
                EnumSet.of(AlertStatus.SUPPRESSED, AlertStatus.CLOSED));
        LEGAL.put(AlertStatus.SUPPRESSED,
                EnumSet.of(AlertStatus.CLOSED));
        LEGAL.put(AlertStatus.CLOSED, EnumSet.noneOf(AlertStatus.class));
    }

    private final Map<String, Alert> alerts = new ConcurrentHashMap<>();
    private final Clock clock;

    public AlertService() {
        this(Clock.systemUTC());
    }

    public AlertService(Clock clock) {
        this.clock = clock;
    }

    /** 登记一条新告警（由检测引擎调用）。同 ID 重复登记会被忽略并返回已有告警。 */
    public Alert register(Alert alert) {
        Alert existing = alerts.putIfAbsent(alert.getAlertId(), alert);
        return existing != null ? existing : alert;
    }

    /**
     * 请求一次状态跃迁。
     *
     * @param expectedVersion 可选；非空时要求与当前版本一致，否则拒绝 VERSION_CONFLICT
     */
    public TransitionResult transition(String alertId, AlertStatus target,
                                       String operator, String note, Long expectedVersion) {
        Alert alert = alerts.get(alertId);
        if (alert == null) {
            return new TransitionResult.Rejected(
                    TransitionError.ALERT_NOT_FOUND, "告警不存在: " + alertId);
        }
        synchronized (alert) {
            if (expectedVersion != null && expectedVersion != alert.getVersion()) {
                return new TransitionResult.Rejected(
                        TransitionError.VERSION_CONFLICT,
                        "期望版本=" + expectedVersion + ", 实际版本=" + alert.getVersion());
            }
            AlertStatus current = alert.getStatus();
            if (current == AlertStatus.CLOSED) {
                return new TransitionResult.Rejected(
                        TransitionError.ALREADY_TERMINAL,
                        "告警已关闭（终态），不允许再跃迁到 " + target);
            }
            if (!LEGAL.get(current).contains(target)) {
                return new TransitionResult.Rejected(
                        TransitionError.ILLEGAL_TRANSITION,
                        "不允许从 " + current + " 跃迁到 " + target);
            }
            alert.applyTransition(target, operator, actionName(target), note, Instant.now(clock));
            return new TransitionResult.Success(alert.snapshot());
        }
    }

    public TransitionResult acknowledge(String alertId, String operator, String note) {
        return transition(alertId, AlertStatus.ACKNOWLEDGED, operator, note, null);
    }

    public TransitionResult suppress(String alertId, String operator, String note) {
        return transition(alertId, AlertStatus.SUPPRESSED, operator, note, null);
    }

    public TransitionResult close(String alertId, String operator, String note) {
        return transition(alertId, AlertStatus.CLOSED, operator, note, null);
    }

    private static String actionName(AlertStatus target) {
        return switch (target) {
            case ACKNOWLEDGED -> "ACKNOWLEDGE";
            case SUPPRESSED -> "SUPPRESS";
            case CLOSED -> "CLOSE";
            case OPEN -> "REOPEN";
        };
    }

    public Optional<Alert> find(String alertId) {
        Alert alert = alerts.get(alertId);
        return alert == null ? Optional.empty() : Optional.of(alert.snapshot());
    }

    public List<Alert> list() {
        return alerts.values().stream().map(Alert::snapshot).toList();
    }
}
