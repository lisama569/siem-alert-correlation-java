package com.github.lisama569.siemalertcorrelationjava.model.event;

/** 归一化拒绝原因（带稳定错误码，便于区分与排查）。 */
public enum RejectionReason {
    MISSING_SOURCE("E101", "事件来源缺失"),
    UNKNOWN_SOURCE("E102", "事件来源无法识别"),
    MISSING_TYPE("E103", "事件类型缺失"),
    UNKNOWN_TYPE("E104", "事件类型无法识别"),
    MISSING_EVENT_TIME("E105", "事件时间缺失"),
    INVALID_EVENT_TIME("E106", "事件时间不是合法的 ISO-8601 时间"),
    EVENT_TIME_IN_FUTURE("E107", "事件时间超出未来容忍范围"),
    INVALID_SOURCE_IP("E108", "源 IP 语义非法"),
    INVALID_DEST_IP("E109", "目标 IP 语义非法");

    private final String code;
    private final String description;

    RejectionReason(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String code() {
        return code;
    }

    public String description() {
        return description;
    }
}
