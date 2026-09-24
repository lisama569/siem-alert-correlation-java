package com.github.lisama569.siemalertcorrelationjava.model;

import java.time.Instant;
import java.util.Map;

/** 归一化后的安全事件。 */
public record SecurityEvent(
        String eventId,
        String source,
        EventType type,
        Instant occurredAt,
        Instant receivedAt,
        Map<String, String> attributes) {
}
