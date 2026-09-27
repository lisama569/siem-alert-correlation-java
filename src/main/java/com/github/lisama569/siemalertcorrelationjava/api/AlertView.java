package com.github.lisama569.siemalertcorrelationjava.api;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** 告警及其处置历史的只读视图。 */
public record AlertView(
        String alertId,
        String ruleId,
        int ruleVersion,
        String title,
        String severity,
        String status,
        long version,
        Instant createdAt,
        List<String> eventIds,
        Map<String, String> enrichment,
        List<Alert.Disposition> history) {

    public static AlertView from(Alert alert) {
        return new AlertView(
                alert.getAlertId(), alert.getRuleId(), alert.getRuleVersion(),
                alert.getTitle(), alert.getSeverity(), alert.getStatus().name(),
                alert.getVersion(), alert.getCreatedAt(), alert.getEventIds(),
                alert.getEnrichment(), alert.getHistory());
    }
}
