package com.github.lisama569.siemalertcorrelationjava.ingest;

import java.util.Map;

/**
 * 接入层的原始事件（各来源字段均为字符串，尚未归一化）。
 *
 * @param occurredAt ISO-8601 时间戳字符串，例如 2026-09-24T08:30:00Z
 */
public record RawEvent(
        String eventId,
        String source,
        String type,
        String occurredAt,
        Map<String, String> attributes) {

    public RawEvent {
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
