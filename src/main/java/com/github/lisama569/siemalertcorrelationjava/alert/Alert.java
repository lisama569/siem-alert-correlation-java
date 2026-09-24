package com.github.lisama569.siemalertcorrelationjava.alert;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 告警实体。
 *
 * <p>可变状态（status / enrichment / history / version）仅允许通过
 * {@link AlertService} 在持有该告警对象监视器锁的前提下修改；
 * {@link #snapshot()} 返回深拷贝，保证对外读取不被并发修改影响。
 */
public class Alert {

    /** 一次处置动作的可追溯记录。 */
    public record Disposition(
            Instant at, String operator, String action,
            AlertStatus from, AlertStatus to, String note) {
    }

    private final String alertId;
    private final String ruleId;
    private final int ruleVersion;
    private final String title;
    private final String severity;
    private final Instant createdAt;
    private final List<String> eventIds;

    private AlertStatus status;
    private long version;
    private final Map<String, String> enrichment;
    private final List<Disposition> history;

    public Alert(String alertId, String ruleId, int ruleVersion, String title,
               String severity, Instant createdAt, List<String> eventIds,
               Map<String, String> enrichment) {
        this.alertId = alertId;
        this.ruleId = ruleId;
        this.ruleVersion = ruleVersion;
        this.title = title;
        this.severity = severity;
        this.createdAt = createdAt;
        this.eventIds = List.copyOf(eventIds);
        this.status = AlertStatus.OPEN;
        this.version = 0;
        this.enrichment = new LinkedHashMap<>(enrichment);
        this.history = new ArrayList<>();
    }

    /** 深拷贝构造，用于对外快照。 */
    private Alert(Alert src) {
        this.alertId = src.alertId;
        this.ruleId = src.ruleId;
        this.ruleVersion = src.ruleVersion;
        this.title = src.title;
        this.severity = src.severity;
        this.createdAt = src.createdAt;
        this.eventIds = src.eventIds;
        this.status = src.status;
        this.version = src.version;
        this.enrichment = new LinkedHashMap<>(src.enrichment);
        this.history = new ArrayList<>(src.history);
    }

    /** 仅允许在 synchronized(alert) 块内调用：应用一次状态跃迁并记录处置历史。 */
    void applyTransition(AlertStatus target, String operator, String action,
                         String note, Instant at) {
        this.history.add(new Disposition(at, operator, action, this.status, target, note));
        this.status = target;
        this.version++;
    }

    /** 仅允许在 synchronized(alert) 块内调用：追加富化字段。 */
    void putEnrichment(String key, String value) {
        this.enrichment.put(key, value);
    }

    public Alert snapshot() {
        synchronized (this) {
            return new Alert(this);
        }
    }

    public String getAlertId() { return alertId; }
    public String getRuleId() { return ruleId; }
    public int getRuleVersion() { return ruleVersion; }
    public String getTitle() { return title; }
    public String getSeverity() { return severity; }
    public Instant getCreatedAt() { return createdAt; }
    public List<String> getEventIds() { return eventIds; }
    public AlertStatus getStatus() { return status; }
    public long getVersion() { return version; }
    public Map<String, String> getEnrichment() { return Collections.unmodifiableMap(enrichment); }
    public List<Disposition> getHistory() { return Collections.unmodifiableList(history); }

    @Override
    public String toString() {
        return "Alert{id=" + alertId + ", rule=" + ruleId + "v" + ruleVersion
                + ", status=" + status + ", version=" + version + "}";
    }
}
