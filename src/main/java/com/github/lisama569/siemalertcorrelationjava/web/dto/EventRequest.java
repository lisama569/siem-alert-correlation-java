package com.github.lisama569.siemalertcorrelationjava.web.dto;

import java.util.Map;

/** POST /api/events 单条原始事件请求体。骨架。 */
public record EventRequest(
        String eventId,
        String source,
        String type,
        String occurredAt,
        Map<String, String> attributes) {
}
