package com.github.lisama569.siemalertcorrelationjava.web.dto;

import java.util.Map;

/** 事件提交请求体（弱类型原始事件）。 */
public record EventRequest(
        String source,
        String type,
        String eventTime,
        String rawId,
        String user,
        String srcIp,
        String dstIp,
        String host,
        Map<String, String> attributes) {
}
