package com.github.lisama569.siemalertcorrelationjava.detection;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 检测引擎：基于滚动（tumbling）时间窗口的多事件关联计数。
 *
 * <p>乱序与迟到语义（确定且可解释）：
 * <ul>
 *   <li>窗口归属只取决于事件的 occurredAt，与到达顺序无关，
 *       因此乱序到达不改变最终窗口计数与判定结论；</li>
 *   <li>每条规则维护水位线 watermark = 该规则已见最大 occurredAt - allowedLateness；
 *       occurredAt 早于水位线的事件被判定为"超出容忍范围的迟到事件"，
 *       被丢弃并在 notes 中记录原因，不参与计数；</li>
 *   <li>同一 (ruleId, ruleVersion, 分组, 窗口) 条件只触发一次告警，
 *       告警 ID 由该四元组确定，重复评估/重复事件不会产生重复告警；</li>
 *   <li>规则变更后版本号变化，新条件按新版本独立评估；
 *       用历史版本重建引擎即可复现历史判定。</li>
 * </ul>
 */
public class DetectionEngine {

    /** 单条规则的运行状态。 */
    private static final class RuleState {
        final Map<String, List<SecurityEvent>> bufferByGroup = new HashMap<>();
        final Map<String, Boolean> firedWindows = new HashMap<>();
        Instant maxEventTime = null;
    }

    private final RuleRegistry registry;
    private final AlertService alertService;
    private final Clock clock;
    private final Map<String, String> hostCriticality;
    private final Map<String, RuleState> states = new HashMap<>();

    public DetectionEngine(RuleRegistry registry, AlertService alertService, Clock clock) {
        this(registry, alertService, clock, Map.of());
    }

    public DetectionEngine(RuleRegistry registry, AlertService alertService, Clock clock,
                           Map<String, String> hostCriticality) {
        this.registry = registry;
        this.alertService = alertService;
        this.clock = clock;
        this.hostCriticality = hostCriticality;
    }

    /** 评估一批已归一化事件，返回新产生的告警与可解释的判定记录。 */
    public synchronized DetectionResult evaluate(List<SecurityEvent> events) {
        List<Alert> newAlerts = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        Map<String, RuleDefinition> rules = registry.snapshot();

        for (SecurityEvent event : events) {
            for (RuleDefinition rule : rules.values()) {
                if (rule.eventType() != event.type()) {
                    continue;
                }
                RuleState state = states.computeIfAbsent(
                        rule.ruleId() + "#v" + rule.version(), k -> new RuleState());

                // 水位线检查：超出容忍范围的迟到事件直接丢弃并记录
                if (state.maxEventTime != null) {
                    Instant watermark = state.maxEventTime.minus(rule.allowedLateness());
                    if (event.occurredAt().isBefore(watermark)) {
                        notes.add("DROP_LATE: 事件 " + event.eventId()
                                + " occurredAt=" + event.occurredAt()
                                + " 早于水位线 " + watermark
                                + " (规则 " + rule.ruleId() + "v" + rule.version() + ")");
                        continue;
                    }
                }
                if (state.maxEventTime == null || event.occurredAt().isAfter(state.maxEventTime)) {
                    state.maxEventTime = event.occurredAt();
                }

                String group = event.attributes().getOrDefault(rule.groupByField(), "<none>");
                List<SecurityEvent> buffer = state.bufferByGroup.computeIfAbsent(
                        group, k -> new ArrayList<>());
                buffer.add(event);
                buffer.sort(Comparator.comparing(SecurityEvent::occurredAt));

                // 滚动窗口：起点按窗口大小对齐到纪元
                long windowMillis = rule.windowSize().toMillis();
                long startMillis = (event.occurredAt().toEpochMilli() / windowMillis) * windowMillis;
                Instant windowStart = Instant.ofEpochMilli(startMillis);
                Instant windowEnd = windowStart.plus(rule.windowSize());

                long count = buffer.stream()
                        .filter(e -> !e.occurredAt().isBefore(windowStart)
                                && e.occurredAt().isBefore(windowEnd))
                        .count();
                notes.add("EVAL: 规则 " + rule.ruleId() + "v" + rule.version()
                        + " 分组=" + group + " 窗口=[" + windowStart + "," + windowEnd + ")"
                        + " 计数=" + count + " 阈值=" + rule.threshold()
                        + " 触发事件=" + event.eventId());

                String windowKey = group + "@" + startMillis;
                if (count >= rule.threshold() && !state.firedWindows.containsKey(windowKey)) {
                    state.firedWindows.put(windowKey, Boolean.TRUE);
                    Alert alert = buildAlert(rule, group, windowStart, windowEnd, buffer);
                    Alert registered = alertService.register(alert);
                    if (registered == alert) {
                        newAlerts.add(alert.snapshot());
                        notes.add("ALERT: 新建告警 " + alert.getAlertId()
                                + " (规则 " + rule.ruleId() + "v" + rule.version()
                                + ", 分组=" + group + ", 窗口起点=" + windowStart + ")");
                    } else {
                        notes.add("ALERT_DEDUP: 告警 " + alert.getAlertId() + " 已存在，跳过");
                    }
                }
            }
        }
        return new DetectionResult(newAlerts, notes);
    }

    private Alert buildAlert(RuleDefinition rule, String group,
                             Instant windowStart, Instant windowEnd,
                             List<SecurityEvent> buffer) {
        List<SecurityEvent> inWindow = buffer.stream()
                .filter(e -> !e.occurredAt().isBefore(windowStart)
                        && e.occurredAt().isBefore(windowEnd))
                .toList();
        String alertId = rule.ruleId() + "-v" + rule.version()
                + "-" + group + "-" + windowStart.toEpochMilli();

        Map<String, String> enrichment = new LinkedHashMap<>();
        enrichment.put("group", group);
        enrichment.put("windowStart", windowStart.toString());
        enrichment.put("windowEnd", windowEnd.toString());
        enrichment.put("eventCount", String.valueOf(inWindow.size()));
        enrichment.put("firstEventAt", inWindow.get(0).occurredAt().toString());
        enrichment.put("lastEventAt", inWindow.get(inWindow.size() - 1).occurredAt().toString());
        enrichment.put("hostCriticality",
                hostCriticality.getOrDefault(group, "UNKNOWN"));

        return new Alert(
                alertId,
                rule.ruleId(),
                rule.version(),
                rule.description() + " [分组=" + group + "]",
                inWindow.size() >= rule.threshold() * 2 ? "HIGH" : "MEDIUM",
                Instant.now(clock),
                inWindow.stream().map(SecurityEvent::eventId).toList(),
                enrichment);
    }
}
