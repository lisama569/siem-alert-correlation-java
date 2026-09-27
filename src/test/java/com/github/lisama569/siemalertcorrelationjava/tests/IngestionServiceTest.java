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

    /** 固定时钟：2026-09-24T12:00:00Z，使"过去/未来时间戳"判定确定可复现。 */
    private static final Clock FIXED =
            Clock.fixed(Instant.parse("2026-09-24T12:00:00Z"), ZoneOffset.UTC);

    private IngestionService service() {
        return new IngestionService(FIXED);
    }

    @Test
    void acceptsWellFormedEvent() {
        IngestionService service = service();
        RawEvent raw = new RawEvent("e1", "firewall", "login_failed",
                "2026-09-24T08:00:00Z", Map.of("user", "alice", "srcIp", "10.0.0.5"));
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
        IngestionService service = service();
        assertReject(service, new RawEvent(null, "firewall", "LOGIN_FAILED",
                "2026-09-24T08:00:00Z", Map.of()), RejectReason.MISSING_EVENT_ID);
        assertReject(service, new RawEvent("e1", " ", "LOGIN_FAILED",
                "2026-09-24T08:00:00Z", Map.of()), RejectReason.MISSING_SOURCE);
        // 来源已收紧：未认可来源必须单独拒绝
        assertReject(service, new RawEvent("e1", "random-syslog", "LOGIN_FAILED",
                "2026-09-24T08:00:00Z", Map.of()), RejectReason.UNKNOWN_SOURCE);
        assertReject(service, new RawEvent("e1", "edr", null,
                "2026-09-24T08:00:00Z", Map.of()), RejectReason.MISSING_TYPE);
        assertReject(service, new RawEvent("e1", "edr", "HACKED",
                "2026-09-24T08:00:00Z", Map.of()), RejectReason.UNKNOWN_EVENT_TYPE);
        assertReject(service, new RawEvent("e1", "edr", "LOGIN_FAILED", null, Map.of()),
                RejectReason.MISSING_OCCURRED_AT);
        assertReject(service, new RawEvent("e1", "edr", "LOGIN_FAILED", "not-a-time", Map.of()),
                RejectReason.INVALID_TIMESTAMP);
        // 来自未来的时间戳单独拒绝
        assertReject(service, new RawEvent("e1", "edr", "LOGIN_FAILED",
                "2026-09-24T13:00:00Z", Map.of()), RejectReason.FUTURE_TIMESTAMP);
        // 网络地址字段值非法单独拒绝
        assertReject(service, new RawEvent("e1", "edr", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("dst_ip", "999.1.2.3")),
                RejectReason.INVALID_IP_ADDRESS);
        // 全部被拒绝，没有静默丢弃，也没有进入去重集合
        log.info("最终状态: acceptedCount={}", service.acceptedCount());
        assertEquals(0, service.acceptedCount());
    }

    @Test
    void validationOrderIsFixedAndStable() {
        IngestionService service = service();
        // 同一条记录同时踩中多个问题：来源非法、类型非法、时间戳来自未来、IP 非法。
        // 校验顺序固定，必须稳定返回第一个命中的原因 UNKNOWN_SOURCE。
        RawEvent broken = new RawEvent("e9", "unknown-source", "HACKED",
                "2026-09-25T00:00:00Z", Map.of("srcIp", "not-an-ip"));
        for (int i = 0; i < 5; i++) {
            IngestResult r = service.ingest(broken);
            IngestResult.Rejected rejected = assertInstanceOf(IngestResult.Rejected.class, r);
            assertEquals(RejectReason.UNKNOWN_SOURCE, rejected.reason(),
                    "同一条记录每次提交的拒绝原因必须一致");
        }
        // 来源合法后，下一个命中的是 UNKNOWN_EVENT_TYPE
        RawEvent broken2 = new RawEvent("e9", "edr", "HACKED",
                "2026-09-25T00:00:00Z", Map.of("srcIp", "not-an-ip"));
        assertEquals(RejectReason.UNKNOWN_EVENT_TYPE, reason(service, broken2));
        // 类型合法后，下一个命中的是 FUTURE_TIMESTAMP
        RawEvent broken3 = new RawEvent("e9", "edr", "LOGIN_FAILED",
                "2026-09-25T00:00:00Z", Map.of("srcIp", "not-an-ip"));
        assertEquals(RejectReason.FUTURE_TIMESTAMP, reason(service, broken3));
        // 时间合法后，最后命中 INVALID_IP_ADDRESS
        RawEvent broken4 = new RawEvent("e9", "edr", "LOGIN_FAILED",
                "2026-09-24T08:00:00Z", Map.of("srcIp", "not-an-ip"));
        assertEquals(RejectReason.INVALID_IP_ADDRESS, reason(service, broken4));
        // 全程被拒，未占用 eventId 名额
        assertEquals(0, service.acceptedCount());
    }

    @Test
    void invalidIpIsRejectedAcrossFieldNameStyles() {
        IngestionService service = service();
        // 多种命名风格都能识别为网络地址字段
        for (String field : new String[]{"srcIp", "dst_ip", "clientIpAddress", "IPV6"}) {
            RawEvent raw = new RawEvent("e-" + field, "proxy", "NETWORK_CONNECTION",
                    "2026-09-24T08:00:00Z", Map.of(field, "1.2.3"));
            assertEquals(RejectReason.INVALID_IP_ADDRESS, reason(service, raw),
                    "字段 " + field + " 应识别为网络地址字段");
        }
        // 合法 IPv4 / IPv6 放行；非地址字段不做 IP 校验
        assertAccepted(service, new RawEvent("ok1", "proxy", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("dst_ip", "192.168.1.1", "user", "alice")));
        assertAccepted(service, new RawEvent("ok2", "proxy", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("clientIpAddress", "2001:db8::1")));
        assertAccepted(service, new RawEvent("ok3", "proxy", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", Map.of("host", "not-an-ip-but-not-ip-field")));
        assertEquals(3, service.acceptedCount());
    }

    @Test
    void rejectedRecordNeverOccupiesDedupSlot() {
        IngestionService service = service();
        RawEvent raw = new RawEvent("e1", "edr", "LOGIN_FAILED",
                "2026-09-25T00:00:00Z", Map.of()); // 未来时间戳
        assertReject(service, raw, RejectReason.FUTURE_TIMESTAMP);
        // 把时间改回过去后，同一 eventId 仍应被接受（之前被拒未占名额）
        RawEvent fixed = new RawEvent("e1", "edr", "LOGIN_FAILED",
                "2026-09-24T08:00:00Z", Map.of());
        assertAccepted(service, fixed);
        assertEquals(1, service.acceptedCount());
    }

    private void assertReject(IngestionService service, RawEvent raw, RejectReason expected) {
        log.info("输入: {}", raw);
        IngestResult result = service.ingest(raw);
        log.info("判定结果: {}", result);
        IngestResult.Rejected rejected = assertInstanceOf(IngestResult.Rejected.class, result);
        assertEquals(expected, rejected.reason());
        assertFalse(rejected.detail().isBlank());
    }

    private RejectReason reason(IngestionService service, RawEvent raw) {
        return assertInstanceOf(IngestResult.Rejected.class, service.ingest(raw)).reason();
    }

    private void assertAccepted(IngestionService service, RawEvent raw) {
        assertInstanceOf(IngestResult.Accepted.class, service.ingest(raw));
    }

    @Test
    void duplicateSubmissionIsIdempotent() {
        IngestionService service = service();
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
