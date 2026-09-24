package com.github.lisama569.siemalertcorrelationjava.alert;

/** 告警状态跃迁失败的可区分原因。 */
public enum TransitionError {
    ALERT_NOT_FOUND,
    ILLEGAL_TRANSITION,
    ALREADY_TERMINAL,
    VERSION_CONFLICT
}
