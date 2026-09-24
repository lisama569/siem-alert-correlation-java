package com.github.lisama569.siemalertcorrelationjava.model.rule;

import com.github.lisama569.siemalertcorrelationjava.model.event.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;

/**
 * 基于时间窗口的多事件关联规则（不可变、带版本）。
 * 同一 ruleId + version 永远代表同一份判定逻辑，保证历史判定可复现；
 * 规则升级必须使用新 version，旧版本始终可用于历史重放。
 *
 * @param threshold          同键事件在满足 maxGap 会话内达到该数量即触发
 * @param windowMs           窗口长度（毫秒），也用于迟到事件的水位归档
 * @param allowedLatenessMs  容忍迟到范围（相对水位线），超出按迟到确定性丢弃
 * @param maxGapMs           相邻命中事件允许的最大时间间隔（会话间隔，毫秒）
 */
public record RuleDefinition(
        String ruleId,
        String version,
        String name,
        EventType eventType,
        CorrelationField correlateBy,
        int threshold,
        long windowMs,
        long allowedLatenessMs,
        long maxGapMs,
        String severity) {

    /** 规则唯一键：规则 ID + 版本。 */
    public String key() {
        return ruleId + ":" + version;
    }

    public static RuleDefinition of(String ruleId, String version, String name,
                                    EventType eventType, CorrelationField correlateBy,
                                    int threshold, long windowMs, long allowedLatenessMs,
                                    long maxGapMs, String severity) {
        return new RuleDefinition(ruleId, version, name, eventType, correlateBy,
                threshold, windowMs, allowedLatenessMs, maxGapMs, severity);
    }

    /** 事件是否命中本规则（类型匹配）。 */
    public boolean matches(SecurityEvent event) {
        return event.type() == eventType;
    }

    /** 按归并字段提取关联键；字段缺失时回退到 "NONE"（确定性，不抛异常）。 */
    public String correlationKeyOf(SecurityEvent event) {
        String value = switch (correlateBy) {
            case SRC_IP -> event.srcIp();
            case USER -> event.user();
            case HOST -> event.host();
        };
        if (value == null || value.isBlank()) {
            return "NONE";
        }
        return value.trim();
    }
}
