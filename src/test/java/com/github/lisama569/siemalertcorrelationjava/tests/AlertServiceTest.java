package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertStatus;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionError;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class AlertServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AlertServiceTest.class);

    private AlertService service;

    @BeforeEach
    void setUp() {
        service = new AlertService();
        service.register(new Alert("a1", "brute-force", 1, "测试告警", "MEDIUM",
                Instant.parse("2026-09-24T08:00:00Z"), List.of("e1", "e2"),
                Map.of("group", "alice")));
    }

    private void logResult(String action, TransitionResult r) {
        log.info("操作={} -> {}", action, r);
    }

    @Test
    void legalLifecycleIsTraceable() {
        logResult("ack", service.acknowledge("a1", "op-1", "确认"));
        logResult("suppress", service.suppress("a1", "op-1", "暂时抑制"));
        logResult("close", service.close("a1", "op-2", "闭环"));

        Alert alert = service.find("a1").orElseThrow();
        log.info("最终状态: {}", alert);
        alert.getHistory().forEach(h -> log.info("  处置历史: {}", h));

        assertEquals(AlertStatus.CLOSED, alert.getStatus());
        assertEquals(3, alert.getHistory().size());
        assertEquals(AlertStatus.OPEN, alert.getHistory().get(0).from());
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.getHistory().get(0).to());
        assertEquals(3, alert.getVersion());
    }

    @Test
    void illegalTransitionsAreRejectedWithDistinctReasons() {
        // 告警不存在
        TransitionResult notFound = service.acknowledge("ghost", "op-1", "");
        logResult("ack ghost", notFound);
        assertRejected(notFound, TransitionError.ALERT_NOT_FOUND);

        // OPEN -> OPEN 不在跃迁表中
        TransitionResult illegal = service.transition("a1", AlertStatus.OPEN, "op-1", "", null);
        logResult("OPEN->OPEN", illegal);
        assertRejected(illegal, TransitionError.ILLEGAL_TRANSITION);

        // 关闭后任何操作都拒绝，且原因与"非法跃迁"可区分
        logResult("close", service.close("a1", "op-1", "关闭"));
        TransitionResult terminal = service.acknowledge("a1", "op-2", "太晚了");
        logResult("ack after close", terminal);
        assertRejected(terminal, TransitionError.ALREADY_TERMINAL);

        Alert alert = service.find("a1").orElseThrow();
        log.info("最终状态: {} (终态未被覆盖)", alert);
        assertEquals(AlertStatus.CLOSED, alert.getStatus());
        assertEquals(1, alert.getHistory().size(), "被拒绝的跃迁不得写入历史");
    }

    @Test
    void staleVersionIsRejected() {
        logResult("ack", service.acknowledge("a1", "op-1", "确认")); // version 0 -> 1
        TransitionResult stale = service.transition(
                "a1", AlertStatus.CLOSED, "op-2", "基于过期视图关闭", 0L);
        logResult("close with expectedVersion=0", stale);
        assertRejected(stale, TransitionError.VERSION_CONFLICT);

        Alert alert = service.find("a1").orElseThrow();
        log.info("最终状态: {}", alert);
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.getStatus());
    }

    private static void assertRejected(TransitionResult r, TransitionError error) {
        TransitionResult.Rejected rejected = assertInstanceOf(TransitionResult.Rejected.class, r);
        assertEquals(error, rejected.error());
        assertFalse(rejected.detail().isBlank());
    }

    @Test
    void concurrentTransitionsAreConsistent() throws InterruptedException {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger closeWins = new AtomicInteger();
        List<TransitionResult> results = new ArrayList<>();
        Object lock = new Object();

        for (int i = 0; i < threads; i++) {
            String op = "op-" + i;
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    // 一半确认、一半关闭，全部同时打到同一条告警上
                    TransitionResult r = (Integer.parseInt(op.substring(3)) % 2 == 0)
                            ? service.acknowledge("a1", op, "并发确认")
                            : service.close("a1", op, "并发关闭");
                    synchronized (lock) {
                        results.add(r);
                    }
                    if (r instanceof TransitionResult.Success s
                            && s.alert().getStatus() == AlertStatus.CLOSED) {
                        closeWins.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        Alert alert = service.find("a1").orElseThrow();
        log.info("并发结果: 成功数={}, 拒绝数={}, closeWins={}",
                results.stream().filter(r -> r instanceof TransitionResult.Success).count(),
                results.stream().filter(r -> r instanceof TransitionResult.Rejected).count(),
                closeWins.get());
        alert.getHistory().forEach(h -> log.info("  处置历史: {}", h));
        log.info("最终状态: {}", alert);

        // 不变量 1：CLOSED 只能发生一次（不会被并发覆盖回非终态）
        assertEquals(1, closeWins.get(), "并发下关闭只能成功一次");
        // 不变量 2：最终必为终态 CLOSED，且之后所有操作都被拒绝
        assertEquals(AlertStatus.CLOSED, alert.getStatus());
        // 不变量 3：历史记录数 == 成功跃迁数 == 版本号，无丢失无重复
        long successes = results.stream()
                .filter(r -> r instanceof TransitionResult.Success).count();
        assertEquals(successes, alert.getHistory().size());
        assertEquals(successes, alert.getVersion());
        // 不变量 4：历史是合法跃迁链（每步的 to 等于下一步的 from）
        for (int i = 1; i < alert.getHistory().size(); i++) {
            assertEquals(alert.getHistory().get(i - 1).to(), alert.getHistory().get(i).from());
        }
    }
}
