package com.github.lisama569.siemalertcorrelationjava.tests.support;

import com.github.lisama569.siemalertcorrelationjava.model.event.EventSource;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import java.time.Instant;
import java.util.Map;

/** 测试夹具：用固定 epoch 时间构造事件，保证测试确定可复现。 */
public final class TestFixtures {

    /** 测试基准时间：2026-09-24T10:00:00Z。 */
    public static final long T0 = Instant.parse("2026-09-24T10:00:00Z").toEpochMilli();
    public static final long SECOND = 1000L;
    public static final long MINUTE = 60 * SECOND;

    private TestFixtures() {
    }

    public static String iso(long epochMs) {
        return Instant.ofEpochMilli(epochMs).toString();
    }

    public static RawEvent raw(String source, String type, String time, String rawId,
                               String user, String srcIp, String dstIp, String host) {
        return new RawEvent(source, type, time, rawId, user, srcIp, dstIp, host, Map.of());
    }

    public static SecurityEvent event(EventSource source, EventType type, long eventTime,
                                      String rawId, String user, String srcIp, String host) {
        return new SecurityEvent(source.name() + "#" + rawId, source, type, eventTime,
                T0, user, srcIp, "10.0.0.1", host, Map.of());
    }

    public static SecurityEvent loginFailed(long eventTime, String rawId, String user) {
        return event(EventSource.AUTH_SERVICE, EventType.LOGIN_FAILED, eventTime, rawId, user,
                "10.0.0.11", null);
    }
}
