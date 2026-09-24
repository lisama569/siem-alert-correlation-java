package com.github.lisama569.siemalertcorrelationjava.model.rule;

import java.util.List;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;

/**
 * 单事件喂给某条规则后的判定结果。
 * fired=true 表示由此事件（作为锚点）产生了一次新的规则命中。
 */
public record FireOutcome(
        String ruleKey,
        String correlationKey,
        boolean fired,
        boolean suppressedDuplicate,
        String fingerprint,
        LateDecision lateDecision,
        long watermarkMs,
        List<SecurityEvent> contributingEvents) {
}
