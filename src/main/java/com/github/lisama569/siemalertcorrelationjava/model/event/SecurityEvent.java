package com.github.lisama569.siemalertcorrelationjava.model.event;

import java.util.Map;

/**
 * 归一化后的安全事件（强类型、时间统一为 epoch 毫秒）。
 * eventId 为确定性标识：来源 + 原始 ID；无原始 ID 时取内容指纹。
 */
public record SecurityEvent(
        String eventId,
        EventSource source,
        EventType type,
        long eventTime,
        long ingestTime,
        String user,
        String srcIp,
        String dstIp,
        String host,
        Map<String, String> attributes) {

    public SecurityEvent {
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
