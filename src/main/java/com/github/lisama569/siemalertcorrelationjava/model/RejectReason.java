package com.github.lisama569.siemalertcorrelationjava.model;

/** 事件接入时的可区分拒绝原因。 */
public enum RejectReason {
    MISSING_EVENT_ID,
    MISSING_SOURCE,
    MISSING_TYPE,
    UNKNOWN_EVENT_TYPE,
    MISSING_OCCURRED_AT,
    INVALID_TIMESTAMP,
    INVALID_FIELD_VALUE
}
