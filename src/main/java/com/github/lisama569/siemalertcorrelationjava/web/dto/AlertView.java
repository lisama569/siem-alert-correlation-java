package com.github.lisama569.siemalertcorrelationjava.web.dto;

import java.util.List;
import java.util.Map;

/** 告警（含富化与处置历史）的只读视图。 */
public record AlertView(
        String alertId,
        String ruleId,
        int ruleVersion,
        String title,
        String severity,
        String status,
        long version,
        String createdAt,
        List<String> eventIds,
        Map<String, String> enrichment,
        List<DispositionView> history) {
}
