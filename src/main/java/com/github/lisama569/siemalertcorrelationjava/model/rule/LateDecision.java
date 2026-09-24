package com.github.lisama569.siemalertcorrelationjava.model.rule;

/** 迟到事件处理结论（确定且可解释）。 */
public enum LateDecision {
    ON_TIME,
    ACCEPTED_WITHIN_LATENESS,
    REJECTED_TOO_LATE
}
