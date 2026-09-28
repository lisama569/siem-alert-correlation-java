package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.RejectReason;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 网络地址收紧接入的自动化覆盖：
 * <ul>
 *   <li>不同命名风格（驼峰/下划线/连字符/点/大小写）下的非法地址都被拒，
 *       且拒绝原因为独立的 {@link RejectReason#INVALID_IP_ADDRESS}；</li>
 *   <li>合法 IPv4/IPv6（含常见压缩写法）放行，user/host 等普通属性不被误伤；</li>
 *   <li>同一条记录多次、并发、重建链路（模拟重启）后，拒绝原因与点名提示完全一致；</li>
 *   <li>批量与幂等下计数、告警不重复不丢失。</li>
 * </ul>
 */
class IpAddressIngestionTest {

    private static final Logger log = LoggerFactory.getLogger(IpAddressIngestionTest.class);

    private static final Instant NOW = Instant.parse("2026-09-27T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String AT = "2026-09-24T08:00:00Z";

    private static IngestionService newService() {
        return new IngestionService(CLOCK);
    }

    private static RawEvent event(String id, Map<String, String> attrs) {
        return new RawEvent(id, "firewall", "NETWORK_CONNECTION", AT, attrs);
    }

    private static IngestResult.Rejected reject(IngestionService svc, RawEvent raw) {
        IngestResult r = svc.ingest(raw);
        return assertInstanceOf(IngestResult.Rejected.class, r);
    }

    // 1. 命名风格无关：所有写法的地址字段，非法值都必须以 INVALID_IP_ADDRESS 拒绝
    @Test
    void rejectsInvalidIpAcrossAllNamingStyles() {
        List<String> invalidValues = List.of("999.1.2.3", "256.0.0.1", "10.0.0", "not-an-ip",
                "1.2.3.4.5", "2001::db8::1", "gggg::1", "1.2.3.4::");
        // 同一语义的字段在各来源里的不同命名风格（插入顺序刻意打乱）
        List<String> styleKeys = List.of(
                "srcIp", "src_ip", "SRC_IP", "src-ip", "src.ip", "SourceIP", "Source_Ip",
                "dstIp", "DST_IP", "destination-ip", "destination_ip", "DESTINATION.IP",
                "sourceIpAddress", "source_ip_address", "clientIpAddress", "client-ip-address",
                "server_ip", "remoteIP", "local_ip", "orig_ip", "resp_ip", "IP", "ip");
        int caseNo = 0;
        for (String key : styleKeys) {
            for (String bad : invalidValues) {
                String id = "style-" + (caseNo++);
                IngestionService svc = newService();
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put(key, bad);
                IngestResult.Rejected r = reject(svc, event(id, attrs));
                assertEquals(RejectReason.INVALID_IP_ADDRESS, r.reason(),
                        "字段 " + key + " 的非法地址必须被拒");
                assertTrue(r.detail().contains(key),
                        "提示必须点名字段: " + key + ", 实际: " + r.detail());
                assertTrue(r.detail().contains(bad),
                        "提示必须带出非法值: " + r.detail());
                assertEquals(0, svc.acceptedCount(), "被拒记录不得进入计数: " + id);
            }
        }
        log.info("命名风格无关拒绝覆盖 {} 个 字段×取值 组合，全部为 INVALID_IP_ADDRESS", caseNo);
    }

    // 2. 合法 IPv4/IPv6（含压缩与内嵌 IPv4）放行；普通属性不做地址校验
    @Test
    void acceptsValidAddressesAndPlainAttributes() {
        List<String> valid = List.of(
                "0.0.0.0", "127.0.0.1", "192.168.1.10", "255.255.255.255",
                "::1", "::", "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001",
                "fe80::1", "::ffff:192.0.2.1", "2001:db8::192.0.2.1",
                "2001:DB8::ABCD", "0:0:0:0:0:0:0:1");
        int caseNo = 0;
        for (String ip : valid) {
            for (String key : List.of("srcIp", "src_ip", "SRC.IP")) {
                IngestionService svc = newService();
                IngestResult r = svc.ingest(event("ok-" + (caseNo++), Map.of(key, ip)));
                assertInstanceOf(IngestResult.Accepted.class, r,
                        "合法地址应放行: " + key + "=" + ip);
                assertEquals(1, svc.acceptedCount());
            }
        }

        // 普通属性即便"看起来不像地址"也不得做地址校验（含 ip 子串陷阱 host/script）
        IngestionService svc = newService();
        IngestResult r = svc.ingest(event("plain-1", Map.of(
                "user", "not-an-ip-but-fine",
                "host", "web-01.example.com",
                "hostname", "999.999",
                "script", "999.1.2.3",
                "username", "alice",
                "srcPort", "99999",
                "ipHint", "maybe-an-ip")));
        assertInstanceOf(IngestResult.Accepted.class, r,
                "不表示地址的普通属性不得被误伤");
        assertEquals(1, svc.acceptedCount());
        log.info("合法地址 {} 组全部放行，普通属性不做地址校验", caseNo);
    }

    // 3. 多个地址字段非法：按字段名升序全部点名，任意属性插入顺序下提示完全一致
    @Test
    void multipleInvalidFieldsReportedInDeterministicOrder() {
        // 同样的键值用不同 Map 插入顺序构造（含乱序键，模拟 HashMap 遍历漂移）
        List<Map<String, String>> orderings = new ArrayList<>();
        Map<String, String> a = new LinkedHashMap<>();
        a.put("zzz_ip", "10.0.0.1");
        a.put("src_ip", "999.1.1.1");
        a.put("local-ip", "bad");
        a.put("dst.ip", "2001::db8::1");
        a.put("user", "bob");
        orderings.add(a);
        Map<String, String> b = new LinkedHashMap<>();
        b.put("dst.ip", "2001::db8::1");
        b.put("user", "bob");
        b.put("local-ip", "bad");
        b.put("zzz_ip", "10.0.0.1");
        b.put("src_ip", "999.1.1.1");
        orderings.add(b);
        orderings.add(new TreeMap<>(a));
        // 合法地址字段存在时不影响其余非法字段被点名
        Map<String, String> c = new LinkedHashMap<>(a);
        c.put("client_ip", "192.168.0.1");
        orderings.add(c);

        String expectedDetail = null;
        for (Map<String, String> attrs : orderings) {
            IngestionService svc = newService();
            IngestResult.Rejected r = reject(svc, event("multi", attrs));
            assertEquals(RejectReason.INVALID_IP_ADDRESS, r.reason());
            // 三个非法字段全部点名，按字段名升序；合法的 client_ip / 普通字段 user 不出现
            String d = r.detail();
            int p0 = d.indexOf("dst.ip=2001::db8::1");
            int p1 = d.indexOf("local-ip=bad");
            int p3 = d.indexOf("src_ip=999.1.1.1");
            assertTrue(p0 >= 0 && p1 > p0 && p3 > p1,
                    "非法字段必须按字段名字典升序全部点名: " + d);
            assertFalse(d.contains("zzz_ip"), "值合法的地址字段不应被点名: " + d);
            assertFalse(d.contains("user="), "普通属性不应出现在地址拒绝提示中: " + d);
            assertEquals(0, svc.acceptedCount());
            if (expectedDetail == null) {
                expectedDetail = d;
            } else {
                assertEquals(expectedDetail, d, "不同属性插入顺序下提示必须逐字一致");
            }
        }
        log.info("多字段非法的确定性提示: {}", expectedDetail);
    }

    // 4. 同一条记录重复提交、重建链路（模拟重启）：原因与提示逐字一致，且永不计数
    @Test
    void repeatedAndRestartedSubmissionYieldsIdenticalRejection() {
        RawEvent raw = event("repeat-multi", Map.of(
                "src_ip", "999.1.1.1",
                "DST-IP", "not-an-ip",
                "user", "alice"));
        IngestionService svc = newService();
        String first = null;
        for (int i = 0; i < 5; i++) {
            IngestResult.Rejected r = reject(svc, raw);
            assertEquals(RejectReason.INVALID_IP_ADDRESS, r.reason());
            if (first == null) {
                first = r.detail();
            } else {
                assertEquals(first, r.detail(), "第 " + (i + 1) + " 次提交提示必须一致");
            }
        }
        assertEquals(0, svc.acceptedCount(), "重复被拒记录始终不进入计数");
        // 服务重建（内存状态清空，等价于重启）后再交一次，结论仍逐字一致
        for (int i = 0; i < 3; i++) {
            IngestResult.Rejected r = reject(newService(), raw);
            assertEquals(RejectReason.INVALID_IP_ADDRESS, r.reason());
            assertEquals(first, r.detail(), "重启后再次提交提示必须一致");
        }
        log.info("重复提交/重启后拒绝结果一致: {}", first);
    }

    // 5. 并发提交同一条多字段非法记录：所有线程拿到逐字相同的拒绝结果
    @Test
    void concurrentSubmissionsYieldIdenticalRejection() throws InterruptedException {
        RawEvent raw = event("concurrent-multi", Map.of(
                "b_ip", "1.2.3",
                "a_ip", "300.0.0.1",
                "client.ip", "xxxx",
                "host", "web-9"));
        int threads = 16;
        IngestionService svc = newService();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        Map<String, Boolean> distinctResults = new ConcurrentHashMap<>();
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                IngestResult result = svc.ingest(raw);
                if (result instanceof IngestResult.Rejected r
                        && r.reason() == RejectReason.INVALID_IP_ADDRESS) {
                    distinctResults.put(r.reason() + "|" + r.detail(), Boolean.TRUE);
                } else {
                    distinctResults.put("UNEXPECTED:" + result, Boolean.TRUE);
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertEquals(1, distinctResults.size(),
                "并发下所有拒绝结果必须逐字一致: " + distinctResults.keySet());
        assertEquals(0, svc.acceptedCount());
        log.info("并发拒绝结果唯一: {}", distinctResults.keySet().iterator().next());
    }

    // 6. 批量混合 + 幂等：被拒不计数不告警；同批重放结论一致，合法事件不重不漏
    @Test
    void batchAndIdempotencyKeepsCountsAndAlertsStable() {
        List<RawEvent> batch = new ArrayList<>();
        // 6 条合法登录失败（user 分组相同，同窗口 -> 1 条告警）
        for (int i = 0; i < 6; i++) {
            batch.add(new RawEvent("ok-" + i, "auth-gateway", "LOGIN_FAILED",
                    String.format("2026-09-24T08:00:%02dZ", i),
                    Map.of("user", "grp-a", "src_ip", "10.0.0." + (i + 1))));
        }
        // 4 条非法地址（不同命名风格，含多字段非法）
        batch.add(event("bad-1", Map.of("src_ip", "999.1.1.1")));
        batch.add(event("bad-2", Map.of("DST-IP", "not-an-ip")));
        batch.add(event("bad-3", Map.of("source.ip", "10.0.0", "client_ip", "2001::db8::1")));
        batch.add(event("bad-4", Map.of("ServerIPAddress", "nope")));

        Set<String> firstRejectDetails = new java.util.TreeSet<>();
        Integer firstAlertCount = null;

        for (int round = 1; round <= 3; round++) {
            // 每轮全新链路重放同一批（round 2/3 同时验证“重启后再交一次”）
            IngestionService svc = newService();
            AlertService alerts = new AlertService(CLOCK);
            RuleRegistry registry = new RuleRegistry();
            registry.register(new com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition(
                    "brute-force-login", 1, "登录失败窗口关联",
                    com.github.lisama569.siemalertcorrelationjava.model.EventType.LOGIN_FAILED,
                    "user", java.time.Duration.ofMinutes(5),
                    java.time.Duration.ofMinutes(1), 3));
            DetectionEngine engine = new DetectionEngine(registry, alerts, CLOCK);

            int accepted = 0, rejected = 0;
            java.util.TreeSet<String> rejectDetails = new java.util.TreeSet<>();
            List<com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent> acceptedEvents =
                    new ArrayList<>();
            for (RawEvent raw : batch) {
                IngestResult r = svc.ingest(raw);
                if (r instanceof IngestResult.Accepted a) {
                    accepted++;
                    acceptedEvents.add(a.event());
                } else if (r instanceof IngestResult.Rejected rr) {
                    rejected++;
                    assertEquals(RejectReason.INVALID_IP_ADDRESS, rr.reason());
                    rejectDetails.add(rr.detail());
                } else {
                    fail("全新链路首轮不应出现 Duplicate: " + r);
                }
            }
            engine.evaluate(acceptedEvents);

            assertEquals(6, accepted, "第" + round + "轮: 合法 6 条全部受理");
            assertEquals(4, rejected, "第" + round + "轮: 非法 4 条全部拒绝");
            assertEquals(6, svc.acceptedCount(), "被拒记录不得进入计数");
            assertEquals(1, alerts.list().size(), "6 条合法事件应恰好 1 条告警");

            // 在同一链路上把整批再交一遍：合法全幂等、非法仍被拒，计数/告警不变
            int duplicates = 0;
            int rejectedAgain = 0;
            for (RawEvent raw : batch) {
                IngestResult r = svc.ingest(raw);
                if (r instanceof IngestResult.Duplicate) {
                    duplicates++;
                } else if (r instanceof IngestResult.Rejected) {
                    rejectedAgain++;
                }
            }
            assertEquals(6, duplicates, "合法事件重提必须全部 Duplicate");
            assertEquals(4, rejectedAgain, "非法事件重提必须仍然被拒");
            assertEquals(6, svc.acceptedCount(), "重提后计数不得变化");
            assertEquals(1, alerts.list().size(), "重提不得新增告警");

            if (firstAlertCount == null) {
                firstAlertCount = alerts.list().size();
                firstRejectDetails.addAll(rejectDetails);
            } else {
                assertEquals(firstAlertCount, alerts.list().size());
                assertEquals(firstRejectDetails, rejectDetails,
                        "多轮重放的拒绝提示集合必须逐轮一致");
            }
            log.info("第 {} 轮: accepted=6, rejected=4, duplicates=6, alerts=1", round);
        }
        // 流式收集仅用于断言可读性：4 条非法记录提示互不相同且都点名各自字段
        assertEquals(4, firstRejectDetails.size());
        assertTrue(firstRejectDetails.stream().allMatch(s -> Stream
                .of("src_ip", "DST-IP", "source.ip", "ServerIPAddress")
                .anyMatch(s::contains)));
    }
}
