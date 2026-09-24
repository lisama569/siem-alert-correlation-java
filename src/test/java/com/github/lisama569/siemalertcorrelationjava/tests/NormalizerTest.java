package com.github.lisama569.siemalertcorrelationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.siemalertcorrelationjava.engine.ingest.EventNormalizer;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventSource;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.event.IngestionOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.event.RejectionReason;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestFixtures;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestLogger;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 归一化测试：成功路径 + 每种拒绝原因都可区分。 */
class NormalizerTest {

    private final EventNormalizer normalizer = new EventNormalizer();
    private final long now = TestFixtures.T0 + 1000L;

    @Test
    void validEventIsNormalizedWithDeterministicId() {
        TestLogger.section("NormalizerTest.validEventIsNormalizedWithDeterministicId");
        RawEvent raw = TestFixtures.raw("auth-service", "login_failed",
                TestFixtures.iso(TestFixtures.T0), "r1", "alice", "10.0.0.11", "10.0.0.1", null);
        TestLogger.input("raw", "source=auth-service type=login_failed rawId=r1");

        IngestionOutcome o1 = normalizer.normalize(raw, now);
        IngestionOutcome o2 = normalizer.normalize(raw, now);
        TestLogger.basis("来源/类型归一化", "AUTH_SERVICE / LOGIN_FAILED（大小写、连字符容忍）");
        TestLogger.state("eventId", o1.eventId());

        assertTrue(o1.accepted());
        assertEquals(EventSource.AUTH_SERVICE, o1.event().source());
        assertEquals(EventType.LOGIN_FAILED, o1.event().type());
        assertEquals(TestFixtures.T0, o1.event().eventTime());
        // 确定性 ID：同输入两次归一化结果一致
        assertEquals(o1.eventId(), o2.eventId());
    }

    @Test
    void eachRejectionReasonIsDistinguishable() {
        TestLogger.section("NormalizerTest.eachRejectionReasonIsDistinguishable");
        record Case(String name, RawEvent raw, RejectionReason expected, String expectCode) {
        }
        long past = TestFixtures.T0;
        var cases = java.util.List.of(
                new Case("缺来源", TestFixtures.raw(null, "LOGIN_FAILED", TestFixtures.iso(past),
                        "b1", "u", "10.0.0.1", "10.0.0.2", null),
                        RejectionReason.MISSING_SOURCE, "E101"),
                new Case("未知来源", TestFixtures.raw("MARS_SIEM", "LOGIN_FAILED", TestFixtures.iso(past),
                        "b2", "u", "10.0.0.1", "10.0.0.2", null),
                        RejectionReason.UNKNOWN_SOURCE, "E102"),
                new Case("缺类型", TestFixtures.raw("AUTH_SERVICE", " ", TestFixtures.iso(past),
                        "b3", "u", "10.0.0.1", "10.0.0.2", null),
                        RejectionReason.MISSING_TYPE, "E103"),
                new Case("未知类型", TestFixtures.raw("AUTH_SERVICE", "FLOATING", TestFixtures.iso(past),
                        "b4", "u", "10.0.0.1", "10.0.0.2", null),
                        RejectionReason.UNKNOWN_TYPE, "E104"),
                new Case("缺时间", TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED", null,
                        "b5", "u", "10.0.0.1", "10.0.0.2", null),
                        RejectionReason.MISSING_EVENT_TIME, "E105"),
                new Case("时间非法", TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED", "yesterday",
                        "b6", "u", "10.0.0.1", "10.0.0.2", null),
                        RejectionReason.INVALID_EVENT_TIME, "E106"),
                new Case("未来时间", TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED",
                        Instant.ofEpochMilli(now + 61_000L).toString(),
                        "b7", "u", "10.0.0.1", "10.0.0.2", null),
                        RejectionReason.EVENT_TIME_IN_FUTURE, "E107"),
                new Case("源IP非法", TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED", TestFixtures.iso(past),
                        "b8", "u", "300.1.2.3", "10.0.0.2", null),
                        RejectionReason.INVALID_SOURCE_IP, "E108"),
                new Case("目标IP非法", TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED", TestFixtures.iso(past),
                        "b9", "u", "10.0.0.1", "not-an-ip", null),
                        RejectionReason.INVALID_DEST_IP, "E109"));

        for (Case c : cases) {
            IngestionOutcome o = normalizer.normalize(c.raw(), now);
            TestLogger.input(c.name(), "rawId=" + c.raw().rawId());
            TestLogger.result("拒绝", o.accepted() ? "ACCEPTED" : o.reason().code() + "/" + o.reason());
            assertFalse(o.accepted(), c.name());
            assertEquals(c.expected(), o.reason(), c.name());
            assertEquals(c.expectCode(), o.reason().code(), c.name());
            assertNull(o.event(), c.name());
            assertNotNull(o.detail(), "拒绝详情不能为空: " + c.name());
        }
    }

    @Test
    void absentIpIsNotIllegalAndContentFingerprintIsStable() {
        TestLogger.section("NormalizerTest.absentIpIsNotIllegalAndContentFingerprintIsStable");
        RawEvent noRawId = new RawEvent("AUTH_SERVICE", "LOGIN_FAILED", TestFixtures.iso(TestFixtures.T0),
                null, "u", null, null, null, Map.of());
        IngestionOutcome o = normalizer.normalize(noRawId, now);
        TestLogger.state("无 rawId/IP 的事件", o.accepted() ? "accepted id=" + o.eventId() : o.reason());
        assertTrue(o.accepted());
        assertTrue(o.eventId().startsWith("AUTH_SERVICE#"));
        assertEquals(o.eventId(), normalizer.normalize(noRawId, now).eventId());
    }
}
