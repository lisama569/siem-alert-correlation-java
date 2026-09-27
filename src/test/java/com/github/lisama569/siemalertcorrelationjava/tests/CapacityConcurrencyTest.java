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
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 容量与并发一致性验收（规模与通过标准见 README §6.3）：
 * <ul>
 *   <li>单批 2000 条事件一次性提交，同一批输入重建链路重放 3 轮，结论逐轮一致；</li>
 *   <li>16 线程同时提交共 4000 条事件（400 组 × 10 条），
 *       计数不重复不丢失、每组恰好 1 条告警；之后 16 线程重复提交同一批，全部幂等；</li>
 *   <li>16 线程同时关闭同一条告警，恰好 1 次成功，最终 CLOSED、版本连续。</li>
 * </ul>
 */
class CapacityConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(CapacityConcurrencyTest.class);

    /** 固定接收时间（2026-09-27），事件时间取此前，避免被未来事件校验拒绝。 */
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-27T00:00:00Z"), ZoneOffset.UTC);

    private static RuleDefinition defaultRule() {
        return new RuleDefinition("brute-force-login", 1,
                "同一账号 5 分钟内登录失败 >= 3 次", EventType.LOGIN_FAILED, "user",
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3);
    }

    private static DetectionEngine newEngine(IngestionService ingestion, AlertService alerts) {
        RuleRegistry registry = new RuleRegistry();
        registry.register(defaultRule());
        return new DetectionEngine(registry, alerts, CLOCK);
    }

    /** 构造 BATCH_SIZE 条事件：200 组 × 10 条，全部落在同一个 5 分钟窗口内。 */
    private static List<RawEvent> buildBatch() {
        List<RawEvent> batch = new ArrayList<>();
        for (int g = 0; g < 200; g++) {
            for (int i = 0; i < 10; i++) {
                String at = String.format("2026-09-24T08:00:%02dZ", i);
                batch.add(new RawEvent("b-g" + g + "-" + i, "auth-gateway",
                        "LOGIN_FAILED", at, Map.of("user", "g" + g)));
            }
        }
        return batch;
    }

    /** 构造 4000 条事件：400 组 × 10 条，同窗口。 */
    private static List<RawEvent> buildConcurrentLoad() {
        List<RawEvent> load = new ArrayList<>();
        for (int g = 0; g < 400; g++) {
            for (int i = 0; i < 10; i++) {
                String at = String.format("2026-09-24T08:00:%02dZ", i);
                load.add(new RawEvent("c-g" + g + "-" + i, "auth-gateway",
                        "LOGIN_FAILED", at, Map.of("user", "c" + g)));
            }
        }
        return load;
    }

    private static List<SecurityEvent> acceptAll(IngestionService ingestion, List<RawEvent> raws) {
        List<SecurityEvent> accepted = new ArrayList<>();
        for (RawEvent raw : raws) {
            IngestResult r = ingestion.ingest(raw);
            if (r instanceof IngestResult.Accepted a) {
                accepted.add(a.event());
            }
        }
        return accepted;
    }

    @Test
    void batchOf2000IsDeterministicAcrossThreeRounds() {
        List<RawEvent> batch = buildBatch();
        Set<String> firstRoundAlertIds = null;

        for (int round = 1; round <= 3; round++) {
            // 每轮全新链路重放同一批输入（与 HTTP /api/events/batch 走的处理路径一致）
            IngestionService ingestion = new IngestionService(CLOCK);
            AlertService alerts = new AlertService(CLOCK);
            DetectionEngine engine = newEngine(ingestion, alerts);

            List<SecurityEvent> accepted = acceptAll(ingestion, batch);
            var detection = engine.evaluate(accepted);

            assertEquals(2000, ingestion.acceptedCount(), "第" + round + "轮: 受理数应为 2000");
            assertEquals(200, alerts.list().size(), "第" + round + "轮: 告警数应为 200");
            // 每个分组最终窗口计数都必须达到 10（不重复、不丢失的计数侧验证）
            Set<String> groupsAtTen = new HashSet<>();
            for (String note : detection.notes()) {
                if (note.contains("计数=10 ")) {
                    int start = note.indexOf("分组=") + 3;
                    groupsAtTen.add(note.substring(start, note.indexOf(' ', start)));
                }
            }
            assertEquals(200, groupsAtTen.size(),
                    "200 个分组都应出现计数=10 的 EVAL 记录: " + groupsAtTen.size());
            Set<String> ids = new HashSet<>();
            for (Alert a : alerts.list()) {
                ids.add(a.getAlertId());
                assertEquals(AlertStatus.OPEN, a.getStatus());
                assertEquals(0, a.getVersion());
                // 告警在计数首达阈值 3 时创建（既有兼容口径），事件为该窗口内最早 3 条
                assertEquals(3, Integer.parseInt(a.getEnrichment().get("eventCount")),
                        "告警在阈值处触发，eventCount 固化为 3: " + a.getAlertId());
                assertEquals(3, a.getEventIds().size());
            }
            log.info("第 {} 轮: 受理=2000, 告警=200, 编号示例={}",
                    round, alerts.list().get(0).getAlertId());

            if (firstRoundAlertIds == null) {
                firstRoundAlertIds = ids;
            } else {
                assertEquals(firstRoundAlertIds, ids,
                        "第" + round + "轮告警编号集合必须与首轮完全一致");
            }
        }
        log.info("3 轮结论逐轮一致: 2000 条 -> 200 条确定性编号告警");
    }

    @Test
    void sixteenThreadsIngest4000EventsWithoutLossOrDuplication() throws InterruptedException {
        IngestionService ingestion = new IngestionService(CLOCK);
        AlertService alerts = new AlertService(CLOCK);
        DetectionEngine engine = newEngine(ingestion, alerts);

        List<RawEvent> load = buildConcurrentLoad();
        // 打乱后分给 16 个线程（每线程 250 条）
        List<RawEvent> shuffled = new ArrayList<>(load);
        Collections.shuffle(shuffled);
        int threads = 16;
        int perThread = shuffled.size() / threads;
        AtomicInteger acceptedByThreads = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);

        for (int t = 0; t < threads; t++) {
            List<RawEvent> slice = shuffled.subList(t * perThread,
                    (t + 1) * perThread);
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                for (RawEvent raw : slice) {
                    IngestResult r = ingestion.ingest(raw);
                    if (r instanceof IngestResult.Accepted a) {
                        acceptedByThreads.incrementAndGet();
                        // 每条事件立即进引擎，最大化引擎与告警登记的并发竞争
                        engine.evaluate(List.of(a.event()));
                    }
                }
            });
        }
        ready.await();
        long start = System.nanoTime();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        // 通过标准：计数不重复不丢失
        assertEquals(4000, acceptedByThreads.get(), "16 线程受理总数应为 4000");
        assertEquals(4000, ingestion.acceptedCount(), "接入层去重计数应为 4000");
        Set<String> expectedAlertIds = new HashSet<>();
        for (int g = 0; g < 400; g++) {
            expectedAlertIds.add("brute-force-login-v1-c" + g + "-1790236800000");
        }
        assertEquals(400, alerts.list().size(), "400 组应恰好产生 400 条告警");
        Set<String> actualAlertIds = new HashSet<>();
        for (Alert a : alerts.list()) {
            actualAlertIds.add(a.getAlertId());
            // 告警在阈值处触发（既有口径），且关联事件必须属于本组（不串组、不重复）
            assertEquals(3, a.getEventIds().size());
            String group = a.getEnrichment().get("group");
            String expectedPrefix = "c-g" + group.substring(1) + "-";
            for (String eventId : a.getEventIds()) {
                assertTrue(eventId.startsWith(expectedPrefix),
                        "告警关联事件串组: " + a.getAlertId() + " -> " + eventId);
            }
        }
        assertEquals(expectedAlertIds, actualAlertIds,
                "告警编号集合必须恰好覆盖 400 个分组：无丢失、无重复");
        log.info("并发提交: 16 线程 × 250 条 = 4000 条, 告警=400, 耗时={}ms", elapsedMs);

        // 第二轮：16 线程重复提交完全相同的 4000 条，必须全部幂等
        ExecutorService repeat = Executors.newFixedThreadPool(threads);
        CountDownLatch ready2 = new CountDownLatch(threads);
        CountDownLatch go2 = new CountDownLatch(1);
        AtomicInteger duplicates = new AtomicInteger();
        for (int t = 0; t < threads; t++) {
            List<RawEvent> slice = shuffled.subList(t * perThread, (t + 1) * perThread);
            repeat.submit(() -> {
                ready2.countDown();
                try {
                    go2.await();
                    for (RawEvent raw : slice) {
                        if (ingestion.ingest(raw) instanceof IngestResult.Duplicate) {
                            duplicates.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready2.await();
        go2.countDown();
        repeat.shutdown();
        assertTrue(repeat.awaitTermination(30, TimeUnit.SECONDS));

        assertEquals(4000, duplicates.get(), "重复提交必须全部判为 DUPLICATE");
        assertEquals(4000, ingestion.acceptedCount(), "重复提交后计数不得变化");
        assertEquals(400, alerts.list().size(), "重复提交不得新增告警");
        log.info("并发重复提交: 4000 条全部幂等, 告警仍为 400 条");
    }

    @Test
    void sixteenThreadsClosingSameAlertExactlyOnce() throws InterruptedException {
        IngestionService ingestion = new IngestionService(CLOCK);
        AlertService alerts = new AlertService(CLOCK);
        DetectionEngine engine = newEngine(ingestion, alerts);
        List<RawEvent> raws = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            raws.add(new RawEvent("lock-" + i, "auth-gateway", "LOGIN_FAILED",
                    String.format("2026-09-24T08:00:0%dZ", i),
                    Map.of("user", "lock-group")));
        }
        engine.evaluate(acceptAll(ingestion, raws));
        assertEquals(1, alerts.list().size());
        String alertId = alerts.list().get(0).getAlertId();

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger successes = new AtomicInteger();
        AtomicInteger terminalRejects = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            String op = "op-" + i;
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    TransitionResult r = alerts.close(alertId, op, "并发关闭");
                    if (r instanceof TransitionResult.Success) {
                        successes.incrementAndGet();
                    } else if (r instanceof TransitionResult.Rejected rr
                            && rr.error().name().equals("ALREADY_TERMINAL")) {
                        terminalRejects.incrementAndGet();
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

        Alert finalAlert = alerts.find(alertId).orElseThrow();
        log.info("并发关闭: 成功={}, 终态拒绝={}, 最终={}, version={}",
                successes.get(), terminalRejects.get(),
                finalAlert.getStatus(), finalAlert.getVersion());

        // 通过标准：关闭恰好成功一次，不会被并发改回；版本与历史连续一致
        assertEquals(1, successes.get(), "并发下关闭只能成功一次");
        assertEquals(15, terminalRejects.get());
        assertEquals(AlertStatus.CLOSED, finalAlert.getStatus());
        assertEquals(1, finalAlert.getVersion(), "版本号必须连续：0 -> 1");
        assertEquals(1, finalAlert.getHistory().size());
        assertEquals(AlertStatus.OPEN, finalAlert.getHistory().get(0).from());
        assertEquals(AlertStatus.CLOSED, finalAlert.getHistory().get(0).to());
    }
}
