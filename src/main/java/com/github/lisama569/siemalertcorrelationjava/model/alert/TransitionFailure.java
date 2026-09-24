package com.github.lisama569.siemalertcorrelationjava.model.alert;

/** 非法状态跃迁的拒绝原因（带稳定错误码）。 */
public enum TransitionFailure {
    ILLEGAL_TRANSITION("A201", "当前状态不允许该跃迁"),
    ALREADY_IN_STATE("A202", "告警已处于目标状态"),
    ACTION_NOT_ALLOWED_ON_CLOSED("A203", "已关闭告警仅允许 REOPEN"),
    VERSION_CONFLICT("A204", "版本冲突：告警已被其他操作更新"),
    ALERT_NOT_FOUND("A205", "告警不存在"),
    INVALID_PAYLOAD("A206", "请求参数非法");

    private final String code;
    private final String description;

    TransitionFailure(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String code() {
        return code;
    }

    public String description() {
        return description;
    }

    /** 按稳定错误码反查；未知码回退到 ILLEGAL_TRANSITION。 */
    public static TransitionFailure valueOfCode(String code) {
        for (TransitionFailure f : values()) {
            if (f.code.equals(code)) {
                return f;
            }
        }
        return ILLEGAL_TRANSITION;
    }
}
