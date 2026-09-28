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
    /** 网络地址属性的值不是合法 IPv4/IPv6（命名风格无关，见 IngestionService）。 */
    INVALID_IP_ADDRESS
}
