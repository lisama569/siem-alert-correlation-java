package com.github.lisama569.siemalertcorrelationjava.model.alert;

import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 告警聚合根（不可变快照）。
 * 每次合法跃迁产生新快照：state 更新、version + 1、审计链追加；
 * 被拒绝的命令只追加一条 accepted=false 的审计记录，version 不变。
 */
public record Alert(
        String alertId,
        String fingerprint,
        String ruleId,
        String ruleVersion,
        String correlationKey,
        AlertState state,
        long version,
        long createdAtMs,
        long updatedAtMs,
        long firstEventTimeMs,
        long lastEventTimeMs,
        String severity,
        int eventCount,
        List<SecurityEvent> contributingEvents,
        Map<String, String> enrichment,
        List<AuditEntry> auditTrail) {

    public Alert {
        contributingEvents = contributingEvents == null ? List.of() : List.copyOf(contributingEvents);
        enrichment = enrichment == null ? Map.of() : Map.copyOf(enrichment);
        auditTrail = auditTrail == null ? List.of() : List.copyOf(auditTrail);
    }

    /** 产生合法状态跃迁后的新快照（version + 1，审计链追加）。 */
    public Alert withTransition(AlertState newState, AuditEntry entry) {
        List<AuditEntry> trail = new ArrayList<>(auditTrail);
        trail.add(entry);
        return new Alert(alertId, fingerprint, ruleId, ruleVersion, correlationKey,
                newState, entry.toVersion(), entry.timestampMs(), entry.timestampMs(),
                firstEventTimeMs, lastEventTimeMs, severity, eventCount,
                contributingEvents, enrichment, List.copyOf(trail));
    }

    /** 追加被拒绝的审计记录（状态与 version 均不变，仅 updatedAtMs 刷新）。 */
    public Alert withRejectedAudit(AuditEntry entry) {
        List<AuditEntry> trail = new ArrayList<>(auditTrail);
        trail.add(entry);
        return new Alert(alertId, fingerprint, ruleId, ruleVersion, correlationKey,
                state, version, createdAtMs, entry.timestampMs(),
                firstEventTimeMs, lastEventTimeMs, severity, eventCount,
                contributingEvents, enrichment, List.copyOf(trail));
    }
}
