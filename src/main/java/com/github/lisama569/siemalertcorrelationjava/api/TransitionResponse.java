package com.github.lisama569.siemalertcorrelationjava.api;

/**
 * 告警处置的 HTTP 响应。
 *
 * @param result SUCCESS / REJECTED
 * @param error  拒绝原因（仅 REJECTED 时非空，取值见 TransitionError）
 */
public record TransitionResponse(
        String result,
        String error,
        String detail,
        AlertView alert) {

    public static TransitionResponse success(AlertView alert) {
        return new TransitionResponse("SUCCESS", null, null, alert);
    }

    public static TransitionResponse rejected(String error, String detail) {
        return new TransitionResponse("REJECTED", error, detail, null);
    }
}
