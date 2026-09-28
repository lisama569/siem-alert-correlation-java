package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.RejectReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 地址字段收紧接入的专项验收：
 * <ul>
 *   <li>不同命名风格（大小写/下划线/连字符）下的非法地址一律以
 *       {@link RejectReason#INVALID_IP_ADDRESS} 拒绝；</li>
 *   <li>合法 IPv4/IPv6（含压缩写法）放行，user/hostname 等普通属性不被误伤，
 *       地址字段缺省/为空的口径与既有实现一致；</li>
 *   <li>同一条记录多次、并发提交以及用全新服务（模拟重启）重放，
 *       拒绝原因与点名提示完全一致；</li>
 *   <li>被拒记录不进入计数。</li>
 * </ul>
 */
class AddressValidationTest {

    private static final Logger log = LoggerFactory.getLogger(AddressValidationTest.class);

    private static final Instant NOW = Instant.parse("2026-09-27T00:00:00Z");
    private static final String AT = "2026-09-24T08:00:00Z";

    private static IngestionService newService() {
        return new IngestionService(Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static RawEvent event(String id, Map<String, String> attrs) {
        return new RawEvent(id, "firewall", "NETWORK_CONNECTION", AT, attrs);
    }

    private static IngestResult.Rejected reject(IngestionService svc, RawEvent raw) {
        IngestResult r = svc.ingest(raw);
        return assertInstanceOf(IngestResult.Rejected.class, r);
    }

    @Test
    void rejectsInvalidAddressesAcrossNamingStyles() {
        // 同一含义字段的不同命名风格：驼峰/全大写/下划线/连字符/混合
        for (String key : List.of("srcIp", "SRCIP", "src_ip", "SRC_IP",
                "src-ip", "Src-Ip", "DST_IP", "destination-ip", "DestinationIp", "IP")) {
            IngestionService svc = newService();
            IngestResult.Rejected r = reject(svc, event("e-" + key, Map.of(key, "999.1.2.3")));
            assertEquals(RejectReason.INVALID_IP_ADDRESS, r.reason(),
                    "命名风格 " + key + " 必须按地址字段拒绝");
            assertTrue(r.detail().contains(key), "提示必须点名字段原名: " + r.detail());
            assertEquals(0, svc.acceptedCount(), "被拒记录不得计数: " + key);
        }

        // 非地址写法（不是地址的字符串）也要拒，且原因可与其它拒绝区分
        IngestionService svc = newService();
        for (String bad : List.of("not-an-ip", "10.0.0", "256.0.0.1",
                "2001:db8::g", "1.2.3.4.5", "999.999.999.999")) {
            IngestResult.Rejected r = reject(svc, event("bad-" + bad.hashCode(),
                    Map.of("src_ip", bad)));
            assertEquals(RejectReason.INVALID_IP_ADDRESS, r.reason());
        }
        assertEquals(0, svc.acceptedCount());
    }

    @Test
    void acceptsValidAddressesAndNonAddressAttributes() {
        IngestionService svc = newService();
        // 合法 IPv4
        assertAccepted(svc, event("v4", Map.of("src_ip", "192.168.1.10")));
        // 合法 IPv6：完整写法 + 常见压缩写法 + 结尾内嵌 IPv4
        for (String addr : List.of(
                "2001:0db8:0000:0000:0000:0000:0000:0001",
                "2001:db8::1", "fe80::1", "::1", "::",
                "2001:db8::192.168.0.1", "::ffff:192.0.2.1")) {
            assertAccepted(svc, event("v6-" + addr.hashCode(), Map.of("dst-ip", addr)));
        }
        // 非地址普通属性：哪怕值"看起来不像地址"也不能误伤
        assertAccepted(svc, event("u1", Map.of("user", "not-an-ip-but-fine")));
        assertAccepted(svc, event("u2", Map.of("hostname", "web-01",
                "srcIp", "10.0.0.5", "dstIp", "10.0.0.6")));
        assertAccepted(svc, event("u3", Map.of("srcPort", "99999")));
        // 地址字段缺省（整个 attributes 为空）按既有口径放行
        assertAccepted(svc, event("missing", Map.of()));
        // 值为空串：与既有 IpValidator 口径一致（存在但为空仍属非法地址）
        IngestResult.Rejected blank = reject(svc, event("blank",
                new LinkedHashMap<>(Map.of("src_ip", "  "))));
        assertEquals(RejectReason.INVALID_IP_ADDRESS, blank.reason());
    }

    private static void assertAccepted(IngestionService svc, RawEvent raw) {
        log.info("应放行: {}", raw);
        IngestResult r = svc.ingest(raw);
        assertInstanceOf(IngestResult.Accepted.class, r, () -> "应被受理: " + raw);
    }

    @Test
    void multipleInvalidAddressFieldsAreReportedDeterministically() {
        // 同一条记录里多个地址字段都非法：点名字段集合与顺序必须稳定
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("src_ip", "999.1.1.1");
        attrs.put("DstIP", "not-an-ip");
        attrs.put("destination-ip", "256.0.0.1");
        attrs.put("user", "alice");
        RawEvent messy = event("multi", attrs);

        IngestionService svc = newService();
        IngestResult.Rejected first = reject(svc, messy);
        assertEquals(RejectReason.INVALID_IP_ADDRESS, first.reason());
        // 按字段名字典序点名，全部非法地址字段一次性列出
        assertEquals("网络地址不合法的字段[DstIP,destination-ip,src_ip], eventId=multi",
                first.detail(), "多个非法字段时提示必须确定: " + first.detail());

        // 同服务内重复提交：原因与提示逐字一致，且不计数
        for (int i = 0; i < 5; i++) {
            IngestResult.Rejected again = reject(svc, messy);
            assertEquals(first.reason(), again.reason());
            assertEquals(first.detail(), again.detail());
        }
        assertEquals(0, svc.acceptedCount());

        // 全新服务（模拟重启）重放：结论仍逐字一致
        IngestionService restarted = newService();
        IngestResult.Rejected afterRestart = reject(restarted, messy);
        assertEquals(first.detail(), afterRestart.detail());
        assertEquals(0, restarted.acceptedCount());
    }

    @Test
    void concurrentSubmissionsOfSameInvalidRecordAreIdentical() throws InterruptedException {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("src_ip", "1.1.1.300");
        attrs.put("DST_IP", "nope");
        attrs.put("source-ip", "10.0.0");
        attrs.put("user", "alice");
        RawEvent raw = event("concurrent-invalid", attrs);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        Map<String, Integer> detailFrequency = new ConcurrentHashMap<>();

        List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
        for (int t = 0; t < threads; t++) {
            futures.add(pool.submit(() -> {
                // 每个线程用自己的服务实例，模拟各自独立接入点的并发提交
                IngestionService svc = newService();
                ready.countDown();
                try {
                    go.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                for (int i = 0; i < 10; i++) {
                    IngestResult.Rejected r = reject(svc, raw);
                    detailFrequency.merge(r.reason() + "|" + r.detail(), 1, Integer::sum);
                }
            }));
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        for (java.util.concurrent.Future<?> f : futures) {
            try { f.get(); } catch (ExecutionException e) {
                throw new RuntimeException(e.getCause());
            }
        }

        log.info("并发拒绝结果分布: {}", detailFrequency);
        assertEquals(1, detailFrequency.size(),
                "16 线程并发提交同一条非法记录，拒绝原因与提示必须只有一种");
        // 被拒记录不计数
        IngestionService probe = newService();
        reject(probe, raw);
        assertEquals(0, probe.acceptedCount());
    }
}
