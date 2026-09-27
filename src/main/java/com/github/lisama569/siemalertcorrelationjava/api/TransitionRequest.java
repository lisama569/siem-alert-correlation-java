package com.github.lisama569.siemalertcorrelationjava.api;

/**
 * 告警处置请求。
 *
 * @param expectedVersion 可选乐观锁版本；非空时要求与告警当前版本一致
 */
public record TransitionRequest(String operator, String note, Long expectedVersion) {
}
