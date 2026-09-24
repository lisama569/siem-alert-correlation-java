package com.github.lisama569.siemalertcorrelationjava.model.event;

import java.util.Map;

/**
 * 接入的原始安全事件（多来源统一入口的弱类型形态）。
 * 时间使用 ISO-8601 字符串（如 2026-09-24T10:00:00Z）。
 */
public record RawEvent(
        String source,
        String type,
        String eventTime,
        String rawId,
        String user,
        String srcIp,
        String dstIp,
        String host,
        Map<String, String> attributes) {

    public RawEvent {
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
