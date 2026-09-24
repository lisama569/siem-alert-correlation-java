package com.github.lisama569.siemalertcorrelationjava.model.event;

/** 归一化后的安全事件类型。 */
public enum EventType {
    LOGIN_FAILED,
    LOGIN_SUCCESS,
    PRIVILEGE_USE,
    MALWARE_DETECTED,
    FIREWALL_BLOCK,
    ACCESS_DENIED,
    WEB_ATTACK_SIGNATURE
}
