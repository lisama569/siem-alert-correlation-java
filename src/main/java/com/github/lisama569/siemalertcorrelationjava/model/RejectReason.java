package com.github.lisama569.siemalertcorrelationjava.model;

/** 事件接入时的可区分拒绝原因。 */
public enum RejectReason {
    MISSING_EVENT_ID,
    MISSING_SOURCE,
    /** source 非空但不在受认可的来源白名单中。 */
    UNKNOWN_SOURCE,
    MISSING_TYPE,
    UNKNOWN_EVENT_TYPE,
    MISSING_OCCURRED_AT,
    INVALID_TIMESTAMP,
    /** occurredAt 晚于当前时间（来自未来的时间戳）。 */
    FUTURE_TIMESTAMP,
    /** 表示网络地址的属性字段值不是合法的 IPv4/IPv6 字面量。 */
    INVALID_IP_ADDRESS,
    INVALID_FIELD_VALUE
}
