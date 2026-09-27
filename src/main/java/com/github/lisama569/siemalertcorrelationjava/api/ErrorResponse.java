package com.github.lisama569.siemalertcorrelationjava.api;

/** 通用错误响应（如告警不存在）。 */
public record ErrorResponse(String error, String detail) {
}
