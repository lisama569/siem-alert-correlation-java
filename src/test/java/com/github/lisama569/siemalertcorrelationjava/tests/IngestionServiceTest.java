package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.RejectReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IngestionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(IngestionServiceTest.class);

    /** 固定接收时间 2026-09-27T00:00:00Z，便于构造"未来事件"用例。 */
    private static final Instant NOW = Instant.parse("2026-09-27T00:00:00Z");

    private final IngestionService service =
            new IngestionService(Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void acceptsWellFormedEvent() {
        RawEvent raw = new RawEvent("e1", "firewall", "login_failed",
                "2026-09-24T08:00:00Z", Map.of("user", "alice", "srcIp", "10.0.0.8"));
        log.info("输入: {}", raw);
        IngestResult result = service.ingest(raw);
        log.info("判定结果: {}", result);

        assertInstanceOf(IngestResult.Accepted.class, result);
        IngestResult.Accepted accepted = (IngestResult.Accepted) result;
        assertEquals(EventType.LOGIN_FAILED, accepted.event().type());
        assertEquals("firewall", accepted.event().source());
        log.info("最终状态: acceptedCount={}", service.acceptedCount());
        assertEquals(1, service.acceptedCount());
    }

    @Test
    void rejectsWithDistinctReasons() {
        assertReject(new RawEvent(null, "firewall", "LOGIN_FAILED", "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.MISSING_EVENT_ID);
        assertReject(new RawEvent("e1", " ", "LOGIN_FAILED", "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.MISSING_SOURCE);
        assertReject(new RawEvent("e1", "firewall", null, "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.MISSING_TYPE);
        assertReject(new RawEvent("e1", "firewall", "HACKED", "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.UNKNOWN_EVENT_TYPE);
        assertReject(new RawEvent("e1", "firewall", "LOGIN_FAILED", null, Map.of()),
                RejectReason.MISSING_OCCURRED_AT);
        assertReject(new RawEvent("e1", "firewall", "LOGIN_FAILED", "not-a-time", Map.of()),
                RejectReason.INVALID_TIMESTAMP);
        // 全部被拒绝，没有静默丢弃，也没有进入去重集合
        log.info("最终状态: acceptedCount={}", service.acceptedCount());
        assertEquals(0, service.acceptedCount());
    }

    @Test
    void rejectsUnknownSource() {
        assertReject(new RawEvent("e1", "random-syslog", "LOGIN_FAILED",
                        "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.UNKNOWN_SOURCE);
        // 与"来源为空"是可区分的两种原因
        assertReject(new RawEvent("e2", "", "LOGIN_FAILED",
                        "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.MISSING_SOURCE);
        assertEquals(0, service.acceptedCount());
    }

    @Test
    void rejectsFutureTimestamp() {
        // 接收时间固定为 2026-09-27T00:00:00Z，更晚的 occurredAt 属于"未来事件"
        assertReject(new RawEvent("e1", "ids", "MALWARE_DETECTED",
                        "2026-09-27T00:00:01Z", Map.of("host", "web-01")),
                RejectReason.FUTURE_TIMESTAMP);
        // 恰好等于当前时间不算未来，应被接受
        IngestResult atNow = service.ingest(new RawEvent("e2", "ids", "MALWARE_DETECTED",
                "2026-09-27T00:00:00Z", Map.of("host", "web-01")));
        log.info("恰好等于当前时间: {}", atNow);
        assertInstanceOf(IngestResult.Accepted.class, atNow);
        // 与"时间格式非法"可区分
        assertReject(new RawEvent("e3", "ids", "MALWARE_DETECTED",
                        "tomorrow", Map.of()),
                RejectReason.INVALID_TIMESTAMP);
    }

    @Test
    void rejectsInvalidIpAttribute() {
        assertReject(new RawEvent("e1", "firewall", "NETWORK_CONNECTION",
                        "2026-09-24T08:00:00Z", Map.of("srcIp", "999.1.2.3")),
                RejectReason.INVALID_IP_ADDRESS);
        assertReject(new RawEvent("e2", "firewall", "NETWORK_CONNECTION",
                        "2026-09-24T08:00:00Z", Map.of("dstIp", "not-an-ip")),
                RejectReason.INVALID_IP_ADDRESS);
        assertReject(new RawEvent("e3", "firewall", "NETWORK_CONNECTION",
                        "2026-09-24T08:00:00Z", Map.of("ip", "10.0.0")),
                RejectReason.INVALID_IP_ADDRESS);
        // 合法 IPv4 / IPv6 放行
        IngestResult v4 = service.ingest(new RawEvent("e4", "firewall", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("srcIp", "192.168.1.10")));
        IngestResult v6 = service.ingest(new RawEvent("e5", "firewall", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("dstIp", "2001:db8::1")));
        log.info("合法 IPv4: {}, 合法 IPv6: {}", v4, v6);
        assertInstanceOf(IngestResult.Accepted.class, v4);
        assertInstanceOf(IngestResult.Accepted.class, v6);
        // 非地址字段不做地址校验
        IngestResult other = service.ingest(new RawEvent("e6", "firewall", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("user", "not-an-ip-but-fine")));
        assertInstanceOf(IngestResult.Accepted.class, other);
        assertEquals(3, service.acceptedCount());
    }

    @Test
    void validationOrderIsDeterministic() {
        // 同时违反多条规则：未知来源 + 非法类型 + 未来时间 + 非法 IP
        // 固定顺序下必须总是报最靠前的 UNKNOWN_SOURCE
        RawEvent messy = new RawEvent("e1", "unknown-src", "HACKED",
                "2999-01-01T00:00:00Z", Map.of("srcIp", "bad"));
        for (int i = 0; i < 3; i++) {
            IngestResult r = service.ingest(messy);
            log.info("第 {} 次提交: {}", i + 1, r);
            IngestResult.Rejected rejected = assertInstanceOf(IngestResult.Rejected.class, r);
            assertEquals(RejectReason.UNKNOWN_SOURCE, rejected.reason(),
                    "同一条记录每次的拒绝原因必须一致");
        }
        // 来源合法但其余均非法：应报 UNKNOWN_EVENT_TYPE（顺序在时间与 IP 之前）
        assertReject(new RawEvent("e2", "ids", "HACKED",
                        "2999-01-01T00:00:00Z", Map.of("srcIp", "bad")),
                RejectReason.UNKNOWN_EVENT_TYPE);
        // 类型也合法：应报 FUTURE_TIMESTAMP（顺序在 IP 之前）
        assertReject(new RawEvent("e3", "ids", "MALWARE_DETECTED",
                        "2999-01-01T00:00:00Z", Map.of("srcIp", "bad")),
                RejectReason.FUTURE_TIMESTAMP);
    }

    private void assertReject(RawEvent raw, RejectReason expected) {
        log.info("输入: {}", raw);
        IngestResult result = service.ingest(raw);
        log.info("判定结果: {}", result);
        IngestResult.Rejected rejected = assertInstanceOf(IngestResult.Rejected.class, result);
        assertEquals(expected, rejected.reason());
        assertFalse(rejected.detail().isBlank());
    }

    @Test
    void duplicateSubmissionIsIdempotent() {
        RawEvent raw = new RawEvent("e1", "ids", "MALWARE_DETECTED",
                "2026-09-24T09:00:00Z", Map.of("host", "web-01"));
        log.info("输入(提交两次): {}", raw);
        IngestResult first = service.ingest(raw);
        IngestResult second = service.ingest(raw);
        log.info("第一次: {}, 第二次: {}", first, second);

        assertInstanceOf(IngestResult.Accepted.class, first);
        IngestResult.Duplicate dup = assertInstanceOf(IngestResult.Duplicate.class, second);
        assertEquals("e1", dup.eventId());
        log.info("最终状态: acceptedCount={} (重复提交未产生重复计数)", service.acceptedCount());
        assertEquals(1, service.acceptedCount());
    }
}
