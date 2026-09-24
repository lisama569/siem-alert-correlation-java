package com.github.lisama569.siemalertcorrelationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.siemalertcorrelationjava.engine.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertAction;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertCommand;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertState;
import com.github.lisama569.siemalertcorrelationjava.model.alert.CommandResult;
import com.github.lisama569.siemalertcorrelationjava.model.alert.TransitionFailure;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.FireOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.rule.LateDecision;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestFixtures;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestLogger;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/** 告警生命周期测试：合法跃迁、非法跃迁原因可区分、版本冲突、审计链完整。 */
class AlertLifecycleTest {

    private AlertService service() {
        return new AlertService(
                Clock.fixed(Instant.ofEpochMilli(TestFixtures.T0), ZoneOffset.UTC),
                new com.github.lisama569.siemalertcorrelationjava.engine.alert.Enricher());
    }

    private Alert seed(AlertService svc) {
        SecurityEvent e = TestFixtures.loginFailed(TestFixtures.T0, "x1", "alice");
        FireOutcome fire = new FireOutcome("R:v1", "alice", true, false,
                "R:v1|alice|AUTH_SERVICE#x1", LateDecision.ON_TIME, TestFixtures.T0, List.of(e));
        return svc.createIfAbsent(fire, new AlertService.RuleContext(
                "R", "v1", "rule", "HIGH", 60_000L, 5_000L));
    }

    private CommandResult act(AlertService svc, String id, AlertAction action, Long version) {
        return svc.apply(new AlertCommand(id, action, "tester", "unit-test", version));
    }

    @Test
    void legalTransitionsAdvanceStateAndVersion() {
        TestLogger.section("AlertLifecycleTest.legalTransitionsAdvanceStateAndVersion");
        AlertService svc = service();
        Alert a = seed(svc);
        long v0 = a.version();
        TestLogger.state("初始", a.state() + " v" + v0);

        assertEquals(AlertState.ACKNOWLEDGED, act(svc, a.alertId(), AlertAction.ACKNOWLEDGE, null).alert().state());
        assertEquals(AlertState.SUPPRESSED, act(svc, a.alertId(), AlertAction.SUPPRESS, null).alert().state());
        Alert reopened = act(svc, a.alertId(), AlertAction.REOPEN, null).alert();
        assertEquals(AlertState.OPEN, reopened.state());
        Alert closed = act(svc, a.alertId(), AlertAction.CLOSE, null).alert();
        assertEquals(AlertState.CLOSED, closed.state());
        Alert reopened2 = act(svc, a.alertId(), AlertAction.REOPEN, null).alert();
        assertEquals(AlertState.OPEN, reopened2.state());
        TestLogger.state("最终", reopened2.state() + " v" + reopened2.version());
        assertTrue(reopened2.version() > v0);
        // 每次跃迁 +1：ACK,SUPPRESS,REOPEN,CLOSE,REOPEN = 5
        assertEquals(v0 + 5, reopened2.version());
    }

    @Test
    void illegalAndNoopTransitionsReturnDistinctReasons() {
        TestLogger.section("AlertLifecycleTest.illegalAndNoopTransitionsReturnDistinctReasons");
        AlertService svc = service();
        Alert a = seed(svc); // OPEN

        // OPEN 上 REOPEN：非法跃迁
        CommandResult illegal = act(svc, a.alertId(), AlertAction.REOPEN, null);
        // OPEN -> ACK
        act(svc, a.alertId(), AlertAction.ACKNOWLEDGE, null);
        // ACKNOWLEDGED 上再 ACKNOWLEDGE：已在目标状态
        CommandResult sameState = act(svc, a.alertId(), AlertAction.ACKNOWLEDGE, null);
        // ACKNOWLEDGED -> CLOSE
        String id = a.alertId();
        act(svc, id, AlertAction.CLOSE, null);
        // CLOSED 上 ACKNOWLEDGE：关闭态仅允许 REOPEN
        CommandResult onClosed = act(svc, id, AlertAction.ACKNOWLEDGE, null);

        TestLogger.result("OPEN+REOPEN", illegal.failure().code() + "/" + illegal.failure());
        TestLogger.result("ACK+ACK", sameState.failure().code() + "/" + sameState.failure());
        TestLogger.result("CLOSED+ACK", onClosed.failure().code() + "/" + onClosed.failure());

        assertFalse(illegal.success());
        assertEquals(TransitionFailure.ILLEGAL_TRANSITION, illegal.failure());
        assertEquals(TransitionFailure.ALREADY_IN_STATE, sameState.failure());
        assertEquals(TransitionFailure.ACTION_NOT_ALLOWED_ON_CLOSED, onClosed.failure());

        // 被拒绝不改变 version，但全部进审计链
        Alert current = svc.get(id).orElseThrow();
        TestLogger.state("审计条数(含拒绝)", current.auditTrail().size());
        assertTrue(current.auditTrail().stream().anyMatch(x -> !x.accepted()
                && x.rejectionCode().equals("A201")));
        assertTrue(current.auditTrail().stream().anyMatch(x -> !x.accepted()
                && x.rejectionCode().equals("A202")));
        assertTrue(current.auditTrail().stream().anyMatch(x -> !x.accepted()
                && x.rejectionCode().equals("A203")));
    }

    @Test
    void optimisticVersionConflictIsRejected() {
        TestLogger.section("AlertLifecycleTest.optimisticVersionConflictIsRejected");
        AlertService svc = service();
        Alert a = seed(svc);
        long stale = a.version();
        act(svc, a.alertId(), AlertAction.ACKNOWLEDGE, null); // version 已 +1

        CommandResult conflict = act(svc, a.alertId(), AlertAction.CLOSE, stale);
        TestLogger.basis("过期 expectedVersion", stale);
        TestLogger.result("冲突结果", conflict.failure().code() + "/" + conflict.failure());
        assertFalse(conflict.success());
        assertEquals(TransitionFailure.VERSION_CONFLICT, conflict.failure());

        CommandResult fresh = act(svc, a.alertId(), AlertAction.CLOSE,
                svc.get(a.alertId()).orElseThrow().version());
        assertTrue(fresh.success());
        assertEquals(AlertState.CLOSED, fresh.alert().state());
    }

    @Test
    void createIsIdempotentByFingerprintAndUnknownAlertIsNotFound() {
        TestLogger.section("AlertLifecycleTest.createIsIdempotentByFingerprintAndUnknownAlert");
        AlertService svc = service();
        Alert a1 = seed(svc);
        Alert a2 = seed(svc);
        TestLogger.state("同指纹两次创建", a1.alertId() + (a1.alertId().equals(a2.alertId()) ? " == 幂等" : " != 重复!"));
        assertEquals(a1.alertId(), a2.alertId());
        assertEquals(1, svc.size());

        CommandResult missing = svc.apply(
                new AlertCommand("ALERT-nope", AlertAction.CLOSE, "t", null, null));
        assertEquals(TransitionFailure.ALERT_NOT_FOUND, missing.failure());
        TestLogger.result("未知告警", missing.failure().code());
    }
}
