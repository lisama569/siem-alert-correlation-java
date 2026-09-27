package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertStatus;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionResult;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.pipeline.EventPipeline;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 批量与并发容量验收（本地可复现规模见 README §6.3）。
 *
 * <ul>
 *   <li>批量：一次性 1000 条；</li>
 *   <li>接入并发：6400 条唯一事件由 64 个线程在同一屏障后并发提交，
 *       随后再并发重放同一批（幂等）；</li>
 *   <li>处置并发：100 条告警，每条被 16 个线程同时处置（8 确认 + 8 关闭）。</li>
 * </ul>
 *
 * <p>通过标准：接受计数精确、无重复无丢失；告警恰好 100 条，每条关联事件精确 64 个；
 * 重放 0 新增接受、0 新增告警；每条告警关闭只成功一次、最终 CLOSED、
 * version == 历史长度。并发验收重复 3 轮，结论每次一致。
 *
 * <p>确定性：所有事件使用同一固定事件时间（同一窗口），规则窗口 1h、迟到容忍 10min，
 * 并发到达顺序不改变水位线与窗口归属，结论与线程调度无关。
 */
class BatchConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(BatchConcurrencyTest.class);

    private static final Clock FIXED =
            Clock.fixed(Instant.parse("2026-09-26T12:00:00Z"), ZoneOffset.UTC);
    private static final String EVENT_AT = "2026-09-26T09:00:00Z";
    private static final long WINDOW_EPOCH = Instant.parse(EVENT_AT).toEpochMilli();

    private static final int GROUPS = 100;
    private static final int PER_GROUP = 64;
    private static final int TOTAL_UNIQUE = GROUPS * PER_GROUP; // 6400
    private static final int INGEST_THREADS = 64;
    private static final int DISPOSE_THREADS = 16;
    private static final int REPEAT_ROUNDS = 3;

    private record Box(EventPipeline pipeline, AlertService alerts, String ruleId) {
    }

    private static Box newBox(long threshold) {
        RuleRegistry registry = new RuleRegistry();
        RuleDefinition rule = new RuleDefinition(
                "bf-concurrency", 1, "并发验收：同账号 1h 内登录失败达到阈值",
                EventType.LOGIN_FAILED, "user",
                Duration.ofHours(1), Duration.ofMinutes(10), threshold);
        registry.register(rule);
        AlertService alerts = new AlertService(FIXED);
        DetectionEngine engine = new DetectionEngine(registry, alerts, FIXED);
        IngestionService ingestion = new IngestionService(FIXED);
        return new Box(new EventPipeline(ingestion, engine, alerts), alerts, rule.ruleId());
    }

    private static RawEvent raw(int i) {
        String user = "user-" + (i % GROUPS);
        return new RawEvent("evt-" + i, "firewall", "LOGIN_FAILED",
                EVENT_AT, Map.of("user", user, "srcIp", "10.0.0." + (1 + (i % 254))));
    }

    @Test
    void batchOf1000IsCountedExactly() {
        // 批量规则阈值 10：1000 条按 100 组循环，每组恰好 10 条，全部触发 -> 100 条告警
        Box box = newBox(10);
        List<RawEvent> batch = new ArrayList<>(1000);
        for (int i = 0; i < 1000; i++) {
            batch.add(raw(i));
        }
        List<IngestResult> results = box.pipeline().submitAll(batch);

        long accepted = results.stream().filter(r -> r instanceof IngestResult.Accepted).count();
        long duplicate = results.stream().filter(r -> r instanceof IngestResult.Duplicate).count();
        long rejected = results.stream().filter(r -> r instanceof IngestResult.Rejected).count();
        assertEquals(1000, accepted, "批量 1000 条应全部受理");
        assertEquals(0, duplicate);
        assertEquals(0, rejected);
        assertEquals(1000, box.pipeline().ingestion().acceptedCount());
        assertEquals(100, box.alerts().list().size(), "每组 10 条达阈值，应产生 100 条告警");
        for (Alert a : box.alerts().list()) {
            assertEquals(10, a.getEventIds().size(), "每条告警关联事件精确不重不漏");
        }
        log.info("批量验收: total=1000 accepted={} duplicate={} rejected={} alerts={}",
                accepted, duplicate, rejected, box.alerts().list().size());
    }

    @RepeatedTest(REPEAT_ROUNDS)
    void concurrentIngestAndDisposeAreConsistent() throws Exception {
        // 并发验收规则阈值 64：6400 条 = 100 组 × 64 条
        Box box = newBox(PER_GROUP);
        List<RawEvent> events = new ArrayList<>(TOTAL_UNIQUE);
        for (int i = 0; i < TOTAL_UNIQUE; i++) {
            events.add(raw(i));
        }

        // 阶段 1：64 线程并发提交 6400 条唯一事件
        Counts wave1 = submitConcurrently(box, events, INGEST_THREADS);
        log.info("阶段1 并发接入: accepted={} duplicate={} rejected={}",
                wave1.accepted.get(), wave1.duplicate.get(), wave1.rejected.get());
        assertEquals(TOTAL_UNIQUE, wave1.accepted.get(), "并发提交不得丢事件");
        assertEquals(0, wave1.duplicate.get(), "唯一事件不应判重");
        assertEquals(0, wave1.rejected.get());
        assertEquals(TOTAL_UNIQUE, box.pipeline().ingestion().acceptedCount());

        List<Alert> alerts = box.alerts().list();
        assertEquals(GROUPS, alerts.size(), "每组恰达阈值，应产生 100 条告警");
        for (Alert a : alerts) {
            assertEquals(PER_GROUP, a.getEventIds().size(),
                    "每条告警关联事件数必须精确，不重不漏");
            assertEquals(AlertStatus.OPEN, a.getStatus());
            assertEquals(0, a.getVersion());
            // 告警 ID 确定性、编号规则与既有一致
            assertEquals(box.ruleId() + "-v1-"
                    + a.getEnrichment().get("group") + "-" + WINDOW_EPOCH, a.getAlertId());
        }

        // 阶段 2：再用 64 线程并发重放同一批 -> 全部重复，0 新增接受、0 新增告警
        Counts wave2 = submitConcurrently(box, events, INGEST_THREADS);
        log.info("阶段2 并发重放: accepted={} duplicate={} rejected={}",
                wave2.accepted.get(), wave2.duplicate.get(), wave2.rejected.get());
        assertEquals(0, wave2.accepted.get(), "重放不得新增接受/计数");
        assertEquals(TOTAL_UNIQUE, wave2.duplicate.get(), "重放必须全部判重");
        assertEquals(0, wave2.rejected.get());
        assertEquals(TOTAL_UNIQUE, box.pipeline().ingestion().acceptedCount());
        assertEquals(GROUPS, box.alerts().list().size(), "重放不得新增告警");

        // 阶段 3：对每条告警，16 线程（8 确认 + 8 关闭）同时处置
        disposeConcurrently(box, alerts);

        // 终态核对：每条都 CLOSED，关闭只成功一次，版本 == 历史长度，且链合法
        for (Alert before : alerts) {
            Alert a = box.alerts().find(before.getAlertId()).orElseThrow();
            assertEquals(AlertStatus.CLOSED, a.getStatus(), "并发处置后最终必须为 CLOSED");
            assertEquals(a.getHistory().size(), a.getVersion(), "版本号必须与历史长度一致");
            for (int i = 1; i < a.getHistory().size(); i++) {
                assertEquals(a.getHistory().get(i - 1).to(), a.getHistory().get(i).from(),
                        "处置历史必须是连续合法跃迁链");
            }
            long closes = a.getHistory().stream().filter(h -> h.to() == AlertStatus.CLOSED).count();
            assertEquals(1, closes, "并发下关闭只能成功一次，终态不得被改回");
        }
        log.info("阶段3 并发处置完成: alerts={} 全部 CLOSED 且版本/历史一致", alerts.size());
    }

    private static final class Counts {
        final AtomicInteger accepted = new AtomicInteger();
        final AtomicInteger duplicate = new AtomicInteger();
        final AtomicInteger rejected = new AtomicInteger();
    }

    /** 用线程池 + CyclicBarrier 让所有线程尽可能同时发起提交。 */
    private Counts submitConcurrently(Box box, List<RawEvent> work, int threads)
            throws InterruptedException {
        Counts counts = new Counts();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        CountDownLatch done = new CountDownLatch(work.size());
        for (int i = 0; i < work.size(); i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    barrier.await();
                    final RawEvent current = work.get(idx);
                    IngestResult r = box.pipeline().submit(current);
                    switch (r) {
                        case IngestResult.Accepted ignored -> counts.accepted.incrementAndGet();
                        case IngestResult.Duplicate ignored -> counts.duplicate.incrementAndGet();
                        case IngestResult.Rejected ignored -> counts.rejected.incrementAndGet();
                    }
                } catch (Exception e) {
                    counts.rejected.incrementAndGet();
                    Thread.currentThread().interrupt();
                    throw new AssertionError(e);
                } finally {
                    done.countDown();
                }
            });
        }
        assertTrue(done.await(60, TimeUnit.SECONDS), "并发接入应在超时前完成");
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        return counts;
    }

    /** 对每条告警起 16 个并发处置：8 个确认 + 8 个关闭，验证状态机一致性。 */
    private void disposeConcurrently(Box box, List<Alert> alerts) throws InterruptedException {
        int totalTasks = alerts.size() * DISPOSE_THREADS;
        ExecutorService pool = Executors.newFixedThreadPool(DISPOSE_THREADS);
        CountDownLatch done = new CountDownLatch(totalTasks);
        Map<String, AtomicInteger> closeWins = new ConcurrentHashMap<>();
        for (Alert a : alerts) {
            closeWins.put(a.getAlertId(), new AtomicInteger());
            for (int t = 0; t < DISPOSE_THREADS; t++) {
                final String id = a.getAlertId();
                final boolean ack = t % 2 == 0; // 8 ack / 8 close
                final String operator = "op-" + t;
                pool.submit(() -> {
                    try {
                        TransitionResult r = ack
                                ? box.alerts().acknowledge(id, operator, "并发确认")
                                : box.alerts().close(id, operator, "并发关闭");
                        if (r instanceof TransitionResult.Success s
                                && s.alert().getStatus() == AlertStatus.CLOSED) {
                            closeWins.get(id).incrementAndGet();
                        }
                    } finally {
                        done.countDown();
                    }
                });
            }
        }
        assertTrue(done.await(60, TimeUnit.SECONDS), "并发处置应在超时前完成");
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        closeWins.forEach((id, wins) ->
                assertEquals(1, wins.get(), "告警 " + id + " 关闭成功次数必须为 1"));
    }
}
