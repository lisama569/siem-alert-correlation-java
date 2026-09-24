package com.github.lisama569.siemalertcorrelationjava.model.rule;

import java.util.List;

/**
 * 规则版本复现报告：对一份历史事件序列，以指定规则版本重放的全部判定。
 */
public record ReplayReport(
        String ruleId,
        String version,
        int inputCount,
        int firedCount,
        int duplicateCount,
        int rejectedLateCount,
        List<FireOutcome> outcomes,
        List<String> fingerprints) {
}
