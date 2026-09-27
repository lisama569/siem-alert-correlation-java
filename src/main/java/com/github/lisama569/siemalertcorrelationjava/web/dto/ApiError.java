package com.github.lisama569.siemalertcorrelationjava.web.dto;

/** 统一错误响应体：调用方据此区分 查不到 / 状态冲突 / 请求非法 等。 */
public record ApiError(String error, String detail) {
}
