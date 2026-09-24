package com.github.lisama569.siemalertcorrelationjava.model.alert;

/** 告警处置审计记录（不可变，保证可追溯）。 */
public record AuditEntry(
        long sequence,
        long timestampMs,
        AlertAction action,
        AlertState fromState,
        AlertState toState,
        String actor,
        String reason,
        boolean accepted,
        String rejectionCode,
        String detail,
        long fromVersion,
        long toVersion) {
}
