package com.github.lisama569.siemalertcorrelationjava.model.event;

/**
 * 单条事件接入结果：
 * 接受（含是否重复标记）或拒绝（含可区分原因与详情）。
 */
public record IngestionOutcome(
        boolean accepted,
        boolean duplicate,
        String eventId,
        SecurityEvent event,
        RejectionReason reason,
        String detail) {
}
