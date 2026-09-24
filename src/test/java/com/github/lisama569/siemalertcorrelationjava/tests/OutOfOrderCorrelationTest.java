package com.github.lisama569.siemalertcorrelationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.siemalertcorrelationjava.engine.correlation.CorrelationEngine;
import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleRegistry;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventSource;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.FireOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.rule.LateDecision;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestFixtures;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestLogger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 乱序/迟到测试：
 * 1) 容忍范围内乱序，最终触发结论与按序到达一致、指纹相同；
 * 2) 超容忍的历史事件确定丢弃；
 * 3) 同会话第 4 个事件不重复触发。
 */
class OutOfOrderCorrelationTest {

    private static final long GAP = 15 * TestFixtures.SECOND;
    private static final long WINDOW = 60 * TestFixtures.SECOND;
    private static final long LATENESS = 5 * TestFixtures.SECOND;

    private RuleDefinition rule() {
        return RuleDefinition.of("R-TEST", "v1", "测试规则", EventType.LOGIN_FAILED,
                com.github.lisama569.siemalertcorrelationjava.model.rule.CorrelationField.USER,
                3, WINDOW, LATENESS, GAP, "HIGH");
    }

    private CorrelationEngine engineWith(RuleDefinition rule) {
        RuleRegistry registry = new RuleRegistry();
        registry.register(rule);
        return new CorrelationEngine(registry);
    }

    private List<FireOutcome> feed(CorrelationEngine engine, List<SecurityEvent> events) {
        List<FireOutcome> results = new ArrayList<>();
        long lastNow = events.stream().mapToLong(SecurityEvent::eventTime).max().orElse(TestFixtures.T0);
        for (SecurityEvent e : events) {
            results.add(engine.processWith(rule(), e, lastNow));
        }
        return results;
    }

    private SecurityEvent f(long offsetSec, String id) {
        return TestFixtures.loginFailed(TestFixtures.T0 + offsetSec * TestFixtures.SECOND, id, "alice");
    }

    @Test
    void inOrderAndOutOfOrderProduceSameConclusion() {
        TestLogger.section("OutOfOrderCorrelationTest.inOrderAndOutOfOrderProduceSameConclusion");
        // 按序：t0,t5,t10；乱序：t0,t10,t4（t4 到达时水位线=10s-5s=5s，4s&lt;5s 属容忍内迟到）
        List<SecurityEvent> inOrder = List.of(f(0, "e0"), f(5, "e1"), f(10, "e2"));
        List<SecurityEvent> outOfOrder = List.of(f(0, "e0"), f(10, "e2"), f(4, "e1"));

        TestLogger.input("按序到达", "t0,t5,t10");
        TestLogger.input("乱序到达", "t0,t10,t4");

        List<FireOutcome> r1 = feed(engineWith(rule()), inOrder);
        List<FireOutcome> r2 = feed(engineWith(rule()), outOfOrder);

        long fires1 = r1.stream().filter(FireOutcome::fired).count();
        long fires2 = r2.stream().filter(FireOutcome::fired).count();
        String fp1 = r1.stream().filter(FireOutcome::fired).map(FireOutcome::fingerprint).findFirst().orElseThrow();
        String fp2 = r2.stream().filter(FireOutcome::fired).map(FireOutcome::fingerprint).findFirst().orElseThrow();

        TestLogger.basis("乱序迟到标记", r2.get(2).lateDecision());
        TestLogger.state("触发次数(按序/乱序)", fires1 + "/" + fires2);
        TestLogger.state("指纹(按序/乱序)", fp1 + "  ==  " + fp2);

        assertEquals(1, fires1);
        assertEquals(1, fires2);
        assertEquals(fp1, fp2, "乱序与按序的触发指纹必须一致");
        assertEquals(LateDecision.ACCEPTED_WITHIN_LATENESS, r2.get(2).lateDecision());
    }

    @Test
    void eventBeyondToleranceIsDeterministicallyRejected() {
        TestLogger.section("OutOfOrderCorrelationTest.eventBeyondToleranceIsDeterministicallyRejected");
        // 先到 t0、t10 推进水位线到 5s；再来一个 t=-60s 的历史事件，远超 5s 容忍
        List<SecurityEvent> events = List.of(f(0, "e0"), f(10, "e2"), f(-60, "ancient"));
        List<FireOutcome> results = feed(engineWith(rule()), events);
        FireOutcome ancient = results.get(2);
        TestLogger.input("历史事件", "eventTime=t0-60s，到达时水位线=" + ancient.watermarkMs());
        TestLogger.state("迟到结论", ancient.lateDecision());
        assertEquals(LateDecision.REJECTED_TOO_LATE, ancient.lateDecision());
        assertFalse(ancient.fired());
    }

    @Test
    void fourthEventInSameSessionIsSuppressedNotRefired() {
        TestLogger.section("OutOfOrderCorrelationTest.fourthEventInSameSessionIsSuppressedNotRefired");
        List<SecurityEvent> events = List.of(f(0, "e0"), f(5, "e1"), f(10, "e2"), f(14, "e3"));
        List<FireOutcome> results = feed(engineWith(rule()), events);
        long fires = results.stream().filter(FireOutcome::fired).count();
        boolean fourthSuppressed = results.get(3).suppressedDuplicate();
        TestLogger.state("触发次数", fires);
        TestLogger.state("第 4 事件是否重复抑制", fourthSuppressed);
        assertEquals(1, fires);
        assertTrue(fourthSuppressed);
    }

    @Test
    void separateSessionAfterGapFiresIndependently() {
        TestLogger.section("OutOfOrderCorrelationTest.separateSessionAfterGapFiresIndependently");
        // 间隔 > maxGap(15s) 的两组三连，应触发两次
        List<SecurityEvent> events = List.of(
                f(0, "s1a"), f(5, "s1b"), f(10, "s1c"),
                f(40, "s2a"), f(45, "s2b"), f(50, "s2c"));
        List<FireOutcome> results = feed(engineWith(rule()), events);
        long fires = results.stream().filter(FireOutcome::fired).count();
        TestLogger.state("两个独立会话触发次数", fires);
        assertEquals(2, fires);
    }

    @Test
    void tolerableLateEventExtendingFiredSessionDoesNotRefire() {
        TestLogger.section("OutOfOrderCorrelationTest.tolerableLateEventExtendingFiredSessionDoesNotRefire");
        // t0,t5,t10 先触发（锚点 e0）；随后两个容忍范围内迟到事件扩张已触发会话，
        // 即使迟到事件使会话锚点前移，也绝不允许二次触发
        List<SecurityEvent> events = List.of(
                f(0, "e0"), f(5, "e1"), f(10, "e2"),   // 触发 1 次
                f(4, "late-extend"),                    // 容忍内迟到（水位线5s，4s&lt;5s）
                f(3, "late-anchor"));                   // 容忍内迟到
        List<FireOutcome> results = feed(engineWith(rule()), events);
        long fires = results.stream().filter(FireOutcome::fired).count();
        TestLogger.basis("迟到扩张事件结论", results.get(3).lateDecision()
                + " suppressed=" + results.get(3).suppressedDuplicate());
        TestLogger.state("总触发次数（必须为1）", fires);
        assertEquals(1, fires);
        assertEquals(LateDecision.ACCEPTED_WITHIN_LATENESS, results.get(3).lateDecision());
        assertTrue(results.get(3).suppressedDuplicate());
        assertTrue(results.get(4).suppressedDuplicate());
    }
}
