package com.github.lisama569.siemalertcorrelationjava.alert;

/** 状态跃迁结果：成功（含跃迁后的告警快照）或拒绝（含可区分原因）。 */
public sealed interface TransitionResult {

    record Success(Alert alert) implements TransitionResult {
    }

    record Rejected(TransitionError error, String detail) implements TransitionResult {
    }
}
