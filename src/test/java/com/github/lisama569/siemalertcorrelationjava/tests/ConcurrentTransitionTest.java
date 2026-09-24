package com.github.lisama569.siemalertcorrelationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.siemalertcorrelationjava.engine.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertAction;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertCommand;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertState;
import com.github.lisama569.siemalertcorrelationjava.model.alert.CommandResult;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.FireOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.rule.LateDecision;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestFixtures;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestLogger;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/**
 * 并发状态变更测试：
 * 大量并发 ACKNOWLEDGE/SUPPRESS/CLOSE/REOPEN 作用于同一告警，
 * 要求：成功跃迁数 = version 增量、版本连续无重复、审计链无丢失、最终状态可解释。
 */
class ConcurrentTransitionTest {

    @Test
    void concurrentTransitionsNeverLoseOrOverwriteState() throws Exception {
        TestLogger.section("ConcurrentTransitionTest.concurrentTransitionsNeverLoseOrOverwriteState");
        AlertService svc = new AlertService(
                Clock.fixed(Instant.ofEpochMilli(TestFixtures.T0), ZoneOffset.UTC),
                new com.github.lisama569.siemalertcorrelationjava.engine.alert.Enricher());
        SecurityEvent e = TestFixtures.loginFailed(TestFixtures.T0, "c1", "alice");
        FireOutcome fire = new FireOutcome("R:v1", "alice", true, false,
                "R:v1|alice|AUTH_SERVICE#c1", LateDecision.ON_TIME, TestFixtures.T0, List.of(e));
        Alert seed = svc.createIfAbsent(fire,
                new AlertService.RuleContext("R", "v1", "r", "HIGH", 60_000L, 5_000L));

        int perAction = 25; // 每类动作 25 个，共 100 个并发命令
        List<Callable<CommandResult>> tasks = new ArrayList<>();
        for (int i = 0; i < perAction; i++) {
            tasks.add(() -> svc.apply(new AlertCommand(seed.alertId(), AlertAction.ACKNOWLEDGE,
                    "u-ack", null, null)));
            tasks.add(() -> svc.apply(new AlertCommand(seed.alertId(), AlertAction.SUPPRESS,
                    "u-sup", null, null)));
            tasks.add(() -> svc.apply(new AlertCommand(seed.alertId(), AlertAction.CLOSE,
                    "u-close", null, null)));
            tasks.add(() -> svc.apply(new AlertCommand(seed.alertId(), AlertAction.REOPEN,
                    "u-reopen", null, null)));
        }

        ExecutorService pool = Executors.newFixedThreadPool(16);
        List<Future<CommandResult>> futures = pool.invokeAll(tasks);
        long success = 0;
        long rejected = 0;
        List<Long> toVersionsObserved = new ArrayList<>();
        for (Future<CommandResult> f : futures) {
            CommandResult r = f.get();
            if (r.success()) {
                success++;
                toVersionsObserved.add(r.alert().version());
            } else {
                rejected++;
            }
        }
        pool.shutdown();

        Alert finalAlert = svc.get(seed.alertId()).orElseThrow();
        long acceptedAudits = finalAlert.auditTrail().stream().filter(a -> a.accepted() && a.action() != null).count();
        long rejectedAudits = finalAlert.auditTrail().stream().filter(a -> !a.accepted()).count();

        TestLogger.input("并发命令总数", tasks.size());
        TestLogger.basis("成功/拒绝", success + "/" + rejected);
        TestLogger.state("最终 version", finalAlert.version());
        TestLogger.state("最终状态", finalAlert.state());
        TestLogger.state("审计: 接受/拒绝", acceptedAudits + "/" + rejectedAudits);

        // 1) 成功跃迁数与 version 增量严格一致（无丢失、无错误覆盖）
        assertEquals(success, finalAlert.version() - seed.version());
        // 2) 每次成功跃迁的版本号在审计链中唯一且连续
        Set<Long> uniqueVersions = new HashSet<>();
        finalAlert.auditTrail().stream().filter(a -> a.accepted() && a.action() != null)
                .forEach(a -> {
                    uniqueVersions.add(a.toVersion());
                    assertEquals(a.fromVersion() + 1, a.toVersion(), "版本必须连续");
                });
        assertEquals(success, uniqueVersions.size(), "成功跃迁版本号不得重复");
        // 3) 每条命令（成功或拒绝）都留下审计
        assertEquals(tasks.size(), acceptedAudits + rejectedAudits);
        // 4) 最终状态是四个状态之一（确定性取值）
        assertTrue(Set.of(AlertState.OPEN, AlertState.ACKNOWLEDGED, AlertState.SUPPRESSED,
                AlertState.CLOSED).contains(finalAlert.state()));
    }

    @Test
    void concurrentSameFingerprintCreateIsIdempotentUnderContention() throws Exception {
        TestLogger.section("ConcurrentTransitionTest.concurrentSameFingerprintCreateIsIdempotentUnderContention");
        AlertService svc = new AlertService(
                Clock.fixed(Instant.ofEpochMilli(TestFixtures.T0), ZoneOffset.UTC),
                new com.github.lisama569.siemalertcorrelationjava.engine.alert.Enricher());
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Alert>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> {
                SecurityEvent e = TestFixtures.loginFailed(TestFixtures.T0, "p1", "alice");
                FireOutcome fire = new FireOutcome("R:v1", "alice", true, false,
                        "R:v1|alice|AUTH_SERVICE#p1", LateDecision.ON_TIME, TestFixtures.T0, List.of(e));
                return svc.createIfAbsent(fire,
                        new AlertService.RuleContext("R", "v1", "r", "HIGH", 60_000L, 5_000L));
            });
        }
        Set<String> ids = new HashSet<>();
        for (Future<Alert> f : pool.invokeAll(tasks)) {
            ids.add(f.get().alertId());
        }
        pool.shutdown();
        TestLogger.state("并发创建得到的不同告警数", ids.size());
        assertEquals(1, ids.size());
        assertEquals(1, svc.size());
    }
}
