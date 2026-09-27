package com.github.lisama569.siemalertcorrelationjava.web;

import com.github.lisama569.siemalertcorrelationjava.web.dto.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * HTTP 异常到统一错误响应的映射：保证调用方拿到的始终是结构化 JSON，
 * 错误码可机读，不暴露堆栈。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    /** 请求体为空、JSON 语法非法或字段类型不匹配。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError notReadable(HttpMessageNotReadableException e) {
        return new ApiError("MALFORMED_REQUEST", "请求体缺失或不是合法 JSON: "
                + rootMessage(e));
    }

    private static String rootMessage(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        return cur.getMessage() == null ? t.getClass().getSimpleName() : cur.getMessage();
    }
}
