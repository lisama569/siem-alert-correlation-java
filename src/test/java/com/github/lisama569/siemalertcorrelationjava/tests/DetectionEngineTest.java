package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionResult;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DetectionEngineTest {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngineTest.class);
    private static final Instant T0 = Instant.parse("2026-09-24T08:00:00Z");

    private RuleRegistry registry;
    private AlertService alertService;
    private DetectionEngine engine;

    @BeforeEach
    void setUp() {
        registry = new RuleRegistry();
        registry.register(rule(1, 3)); // 阈值 3
        alertService = new AlertService();
        engine = newEngine(registry, alertService);
    }

    private static RuleDefinition rule(int version, long threshold) {
        return new RuleDefinition("brute-force", version, "暴力破解检测",
                EventType.LOGIN_FAILED, "user",
                Duration.ofMinutes(5), Duration.ofMinutes(1), threshold);
    }

    private static DetectionEngine newEngine(RuleRegistry reg, AlertService svc) {
        return new DetectionEngine(reg, svc, Clock.fixed(T0, ZoneOffset.UTC));
    }

    private static SecurityEvent ev(String id, String user, String at) {
        return new SecurityEvent(id, "auth", EventType.LOGIN_FAILED,
                Instant.parse(at), Instant.parse(at), Map.of("user", user));
    }

    @Test
    void outOfOrderArrivalYieldsSameConclusion() {
        // 乱序但都在 allowedLateness(1min) 容忍范围内
        List<SecurityEvent> inOrder = List.of(
                ev("e1", "alice", "2026-09-24T08:00:00Z"),
                ev("e2", "alice", "2026-09-24T08:00:20Z"),
                ev("e3", "alice", "2026-09-24T08:00:40Z"));
        List<SecurityEvent> shuffled = new ArrayList<>(inOrder);
        Collections.reverse(shuffled); // 乱序到达

        DetectionResult r1 = engine.evaluate(inOrder);
        log.info("顺序到达 notes:"); r1.notes().forEach(n -> log.info("  {}", n));

        DetectionEngine engine2 = newEngine(registry, new AlertService());
        DetectionResult r2 = engine2.evaluate(shuffled);
        log.info("乱序到达 notes:"); r2.notes().forEach(n -> log.info("  {}", n));

        log.info("最终状态: 顺序告警={}, 乱序告警={}", r1.newAlerts(), r2.newAlerts());
        assertEquals(1, r1.newAlerts().size());
        assertEquals(1, r2.newAlerts().size());
        // 告警 ID 由 (规则, 版本, 分组, 窗口) 决定，与到达顺序无关
        assertEquals(r1.newAlerts().get(0).getAlertId(), r2.newAlerts().get(0).getAlertId());
        assertEquals(r1.newAlerts().get(0).getEventIds(), r2.newAlerts().get(0).getEventIds());
    }

    @Test
    void lateEventBeyondToleranceIsDroppedWithReason() {
        DetectionResult first = engine.evaluate(List.of(
                ev("e1", "bob", "2026-09-24T08:10:00Z")));
        // 水位线 = 08:10 - 1min = 08:09；08:00 的事件超出容忍范围
        DetectionResult second = engine.evaluate(List.of(
                ev("e2", "bob", "2026-09-24T08:00:00Z")));

        log.info("迟到事件判定 notes:"); second.notes().forEach(n -> log.info("  {}", n));
        assertTrue(second.notes().stream().anyMatch(n -> n.startsWith("DROP_LATE")),
                "应记录迟到丢弃原因");
        assertTrue(second.newAlerts().isEmpty());
        log.info("最终状态: newAlerts={}, 告警总数={}", second.newAlerts(), alertService.list());
    }

    @Test
    void duplicateEventsDoNotDoubleCountOrDoubleAlert() {
        // 接入层已去重；这里验证引擎侧：同一告警条件重复评估只产生一条告警
        List<SecurityEvent> events = List.of(
                ev("e1", "carol", "2026-09-24T08:00:00Z"),
                ev("e2", "carol", "2026-09-24T08:01:00Z"),
                ev("e3", "carol", "2026-09-24T08:02:00Z"));
        DetectionResult r1 = engine.evaluate(events);
        DetectionResult r2 = engine.evaluate(events); // 整批重复提交到引擎
        log.info("第一次: {} 条新告警; 第二次: {} 条新告警",
                r1.newAlerts().size(), r2.newAlerts().size());
        r2.notes().forEach(n -> log.info("  {}", n));

        assertEquals(1, r1.newAlerts().size());
        assertEquals(0, r2.newAlerts().size(), "同一条件不得重复触发新告警");
        log.info("最终状态: 告警总数={}", alertService.list().size());
        assertEquals(1, alertService.list().size());
    }

    @Test
    void ruleChangeKeepsHistoryReproducible() {
        // 第一阶段：v1 阈值 3，两个事件不触发
        List<SecurityEvent> events = List.of(
                ev("e1", "dave", "2026-09-24T08:00:00Z"),
                ev("e2", "dave", "2026-09-24T08:01:00Z"));
        DetectionResult before = engine.evaluate(events);
        log.info("规则 v1(阈值3) 判定: 新告警={}", before.newAlerts().size());
        assertEquals(0, before.newAlerts().size());

        // 规则变更：v2 阈值降为 2，用全新引擎重放同一事件流 -> 可复现且按新版本判定
        RuleRegistry reg2 = new RuleRegistry();
        reg2.register(rule(1, 3));
        reg2.register(rule(2, 2));
        assertThrows(IllegalArgumentException.class, () -> reg2.register(rule(2, 5)),
                "版本必须严格递增");

        DetectionEngine replay = newEngine(reg2, new AlertService());
        DetectionResult after = replay.evaluate(events);
        log.info("规则 v2(阈值2) 重放判定: 新告警={}", after.newAlerts().size());
        after.notes().forEach(n -> log.info("  {}", n));
        assertEquals(1, after.newAlerts().size());
        Alert alert = after.newAlerts().get(0);
        assertEquals(2, alert.getRuleVersion(), "告警应记录触发它的规则版本");
        log.info("最终状态: alert={}, enrichment={}", alert, alert.getEnrichment());

        // 用历史版本 v1 重放，结论必须与当初一致（复现历史判定）
        RuleRegistry regV1 = new RuleRegistry();
        regV1.register(rule(1, 3));
        DetectionResult replayV1 = newEngine(regV1, new AlertService()).evaluate(events);
        log.info("以 v1 重放: 新告警={} (应与历史一致=0)", replayV1.newAlerts().size());
        assertEquals(0, replayV1.newAlerts().size());
    }
}
