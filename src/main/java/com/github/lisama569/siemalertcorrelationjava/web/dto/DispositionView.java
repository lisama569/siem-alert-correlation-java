package com.github.lisama569.siemalertcorrelationjava.web.dto;

/** 告警处置历史一条记录的只读视图。 */
public record DispositionView(
        String at, String operator, String action,
        String from, String to, String note) {
}
