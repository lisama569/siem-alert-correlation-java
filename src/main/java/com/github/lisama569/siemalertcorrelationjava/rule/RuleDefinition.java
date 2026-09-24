package com.github.lisama569.siemalertcorrelationjava.rule;

import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import java.time.Duration;

/** 检测规则定义（不可变，带版本号以支持复现历史判定）。 */
public record RuleDefinition(
        String ruleId,
        int version,
        String description,
        EventType eventType,
        String groupByField,
        Duration windowSize,
        Duration allowedLateness,
        long threshold) {
}
