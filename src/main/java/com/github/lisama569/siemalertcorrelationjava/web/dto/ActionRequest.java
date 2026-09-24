package com.github.lisama569.siemalertcorrelationjava.web.dto;

/** 告警处置请求体。 */
public record ActionRequest(
        String action,
        String actor,
        String reason,
        Long expectedVersion) {
}
