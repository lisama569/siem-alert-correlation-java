package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionResult;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 批量 + 幂等口径下地址收紧的验收：
 * <ul>
 *   <li>同一批输入多跑几遍（每轮全新链路，模拟重启），受理/拒绝/告警结论一致；</li>
 *   <li>非法地址记录（含命名风格变体）一律拒绝且不计数、不进检测、不产生告警；</li>
 *   <li>合法记录重复整批提交时全部判重，计数与告警不重不漏。</li>
 * </ul>
 */
class BatchAddressIdempotencyTest {

    private static final Logger log = LoggerFactory.getLogger(BatchAddressIdempotencyTest.class);

    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-27T00:00:00Z"), ZoneOffset.UTC);

    /** 构造一批混合记录：6 条合法（同账号 3 条触发 1 告警）+ 3 条非法地址（命名风格各异）。 */
    private static List<RawEvent> buildMixedBatch() {
        List<RawEvent> batch = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            batch.add(new RawEvent("ok-" + i, "auth-gateway", "LOGIN_FAILED",
                    String.format("2026-09-24T08:00:%02dZ", i),
                    Map.of("user", "batch-user")));
        }
        batch.add(new RawEvent("bad-1", "firewall", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("src_ip", "999.1.1.1")));
        batch.add(new RawEvent("bad-2", "firewall", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("DST-IP", "not-an-address")));
        // 多个地址字段同时非法
        Map<String, String> multi = new LinkedHashMap<>();
        multi.put("srcIp", "10.0.0");
        multi.put("destination_ip", "256.0.0.1");
        multi.put("user", "batch-user");
        batch.add(new RawEvent("bad-3", "firewall", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", multi));
        return batch;
    }

    private record Outcome(int accepted, int duplicates, int rejected,
                           int alertCount, List<String> rejectedDetails) {
    }

    private static Outcome runOnce(List<RawEvent> batch) {
        IngestionService ingestion = new IngestionService(CLOCK);
        AlertService alerts = new AlertService(CLOCK);
        RuleRegistry registry = new RuleRegistry();
        registry.register(new RuleDefinition("brute-force-login", 1,
                "同一账号 5 分钟内登录失败 >= 3 次", EventType.LOGIN_FAILED, "user",
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3));
        DetectionEngine engine = new DetectionEngine(registry, alerts, CLOCK);

        List<com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent> accepted =
                new ArrayList<>();
        int duplicates = 0;
        int rejected = 0;
        List<String> rejectedDetails = new ArrayList<>();
        for (RawEvent raw : batch) {
            IngestResult r = ingestion.ingest(raw);
            if (r instanceof IngestResult.Accepted a) {
                accepted.add(a.event());
            } else if (r instanceof IngestResult.Duplicate) {
                duplicates++;
            } else {
                rejected++;
                IngestResult.Rejected rr = (IngestResult.Rejected) r;
                assertEquals(com.github.lisama569.siemalertcorrelationjava.model.RejectReason
                        .INVALID_IP_ADDRESS, rr.reason());
                rejectedDetails.add(rr.detail());
            }
        }
        DetectionResult detection = engine.evaluate(accepted);
        return new Outcome(accepted.size(), duplicates, rejected,
                detection.newAlerts().size(), rejectedDetails);
    }

    @Test
    void mixedBatchIsStableAcrossRoundsAndIdempotentOnReplay() {
        List<RawEvent> batch = buildMixedBatch();
        Outcome first = null;
        for (int round = 1; round <= 3; round++) {
            Outcome o = runOnce(batch);
            log.info("第 {} 轮: accepted={}, duplicates={}, rejected={}, alerts={}, details={}",
                    round, o.accepted(), o.duplicates(), o.rejected(),
                    o.alertCount(), o.rejectedDetails());
            assertEquals(6, o.accepted(), "第" + round + "轮: 仅 6 条合法记录被受理");
            assertEquals(0, o.duplicates());
            assertEquals(3, o.rejected(), "第" + round + "轮: 3 条非法地址必须全部拒绝");
            assertEquals(1, o.alertCount(), "第" + round + "轮: 恰好 1 条告警，非法记录不进检测");
            if (first == null) {
                first = o;
            } else {
                assertEquals(first.rejectedDetails(), o.rejectedDetails(),
                        "同一批输入多轮（含重启重放）拒绝提示必须逐字一致");
            }
        }

        // 同一服务实例上整批再交一次：6 条全部判重，计数与告警都不变；
        // 非法记录仍然被拒（拒绝优先于去重，且从不进入去重集合）
        IngestionService ingestion = new IngestionService(CLOCK);
        AlertService alerts = new AlertService(CLOCK);
        RuleRegistry registry = new RuleRegistry();
        registry.register(new RuleDefinition("brute-force-login", 1,
                "同一账号 5 分钟内登录失败 >= 3 次", EventType.LOGIN_FAILED, "user",
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3));
        DetectionEngine engine = new DetectionEngine(registry, alerts, CLOCK);

        int firstAccepted = consume(ingestion, engine, batch);
        int alertCountAfterFirst = alerts.list().size();
        int secondAccepted = consume(ingestion, engine, batch);
        assertEquals(6, firstAccepted);
        assertEquals(0, secondAccepted, "重复整批提交不得新增受理/计数");
        assertEquals(6, ingestion.acceptedCount(), "计数不重不漏，仍为 6");
        assertEquals(alertCountAfterFirst, alerts.list().size(), "重复提交不得新增告警");
        for (Alert a : alerts.list()) {
            assertEquals(3, a.getEventIds().size(), "告警关联事件不重复");
        }
        log.info("重复整批提交: acceptedCount={}, alerts={}",
                ingestion.acceptedCount(), alerts.list().size());
    }

    /** 顺序消费一批，返回本轮 Accepted 数量（Duplicate/Rejected 不计）。 */
    private static int consume(IngestionService ingestion, DetectionEngine engine,
                               List<RawEvent> batch) {
        int accepted = 0;
        for (RawEvent raw : batch) {
            IngestResult r = ingestion.ingest(raw);
            if (r instanceof IngestResult.Accepted a) {
                accepted++;
                engine.evaluate(List.of(a.event()));
            }
        }
        return accepted;
    }
}
