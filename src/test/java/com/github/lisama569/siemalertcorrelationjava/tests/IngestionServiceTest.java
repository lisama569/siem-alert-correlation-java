package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.RejectReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IngestionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(IngestionServiceTest.class);

    private final IngestionService service = new IngestionService();

    @Test
    void acceptsWellFormedEvent() {
        RawEvent raw = new RawEvent("e1", "firewall", "login_failed",
                "2026-09-24T08:00:00Z", Map.of("user", "alice"));
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
        assertReject(new RawEvent(null, "s", "LOGIN_FAILED", "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.MISSING_EVENT_ID);
        assertReject(new RawEvent("e1", " ", "LOGIN_FAILED", "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.MISSING_SOURCE);
        assertReject(new RawEvent("e1", "s", null, "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.MISSING_TYPE);
        assertReject(new RawEvent("e1", "s", "HACKED", "2026-09-24T08:00:00Z", Map.of()),
                RejectReason.UNKNOWN_EVENT_TYPE);
        assertReject(new RawEvent("e1", "s", "LOGIN_FAILED", null, Map.of()),
                RejectReason.MISSING_OCCURRED_AT);
        assertReject(new RawEvent("e1", "s", "LOGIN_FAILED", "not-a-time", Map.of()),
                RejectReason.INVALID_TIMESTAMP);
        // 全部被拒绝，没有静默丢弃，也没有进入去重集合
        log.info("最终状态: acceptedCount={}", service.acceptedCount());
        assertEquals(0, service.acceptedCount());
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
