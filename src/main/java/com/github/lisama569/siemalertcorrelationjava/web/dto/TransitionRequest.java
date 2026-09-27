package com.github.lisama569.siemalertcorrelationjava.web.dto;

/**
 * 告警处置请求体。
 *
 * @param action   ACKNOWLEDGE / SUPPRESS / CLOSE（也可由 URL 决定，二者一致）
 * @param operator 操作人，可空（默认 anonymous）
 * @param note     备注，可空
 * @param expectedVersion 可选乐观锁版本
 */
public record TransitionRequest(String action, String operator, String note,
                                Long expectedVersion) {
}
