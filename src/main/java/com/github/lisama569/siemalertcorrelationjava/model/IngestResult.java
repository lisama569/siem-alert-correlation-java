package com.github.lisama569.siemalertcorrelationjava.model;

/** 事件接入结果：接受 / 重复 / 拒绝（含可区分原因）。 */
public sealed interface IngestResult {

    record Accepted(SecurityEvent event) implements IngestResult {
    }

    record Duplicate(String eventId) implements IngestResult {
    }

    record Rejected(RejectReason reason, String detail) implements IngestResult {
    }
}
