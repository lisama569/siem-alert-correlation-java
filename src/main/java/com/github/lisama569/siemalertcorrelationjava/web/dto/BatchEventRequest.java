package com.github.lisama569.siemalertcorrelationjava.web.dto;

import java.util.List;

/** POST /api/events/batch 批量事件请求体。骨架。 */
public record BatchEventRequest(List<EventRequest> events) {
}
