package com.github.lisama569.siemalertcorrelationjava.model;

/** 事件接入时的可区分拒绝原因。 */
public enum RejectReason {
    MISSING_EVENT_ID,
    MISSING_SOURCE,
    UNKNOWN_SOURCE,
    MISSING_TYPE,
    UNKNOWN_EVENT_TYPE,
    MISSING_OCCURRED_AT,
    INVALID_TIMESTAMP,
    FUTURE_TIMESTAMP,
    /** 属性值不是合法网络地址（独立于其它字段值错误，可按原因区分）。 */
    INVALID_IP_ADDRESS
}
