package com.github.lisama569.siemalertcorrelationjava.engine.alert;

import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * 告警富化器：仅使用进程内信息（内置威胁情报表 + 告警自身元数据），
 * 不发起任何网络/外部服务调用。
 */
@Component
public class Enricher {

    /** 内置本地情报表（演示用，确定性）。 */
    private static final Map<String, String> LOCAL_INTEL = Map.of(
            "203.0.113.66", "KNOWN_BAD_IP:brute-force-infrastructure",
            "198.51.100.23", "KNOWN_BAD_IP:malware-c2",
            "10.0.0.254", "SUSPICIOUS_PRIVATE_IP:lateral-movement-candidate");

    /** 内置重点关注账户表。 */
    private static final Map<String, String> WATCH_USERS = Map.of(
            "root", "PRIVILEGED_ACCOUNT",
            "admin", "PRIVILEGED_ACCOUNT",
            "svc_backup", "SERVICE_ACCOUNT");

    public Map<String, String> enrich(Alert alert) {
        Map<String, String> data = new LinkedHashMap<>();
        data.put("ruleId", alert.ruleId());
        data.put("ruleVersion", alert.ruleVersion());
        data.put("severity", alert.severity());
        data.put("correlationKey", alert.correlationKey());
        data.put("matchedEventCount", String.valueOf(alert.eventCount()));

        alert.contributingEvents().stream()
                .map(SecurityEvent::srcIp)
                .filter(ip -> ip != null && LOCAL_INTEL.containsKey(ip))
                .findFirst()
                .ifPresent(ip -> data.put("threatIntel.srcIp", LOCAL_INTEL.get(ip)));

        alert.contributingEvents().stream()
                .map(SecurityEvent::user)
                .filter(u -> u != null && WATCH_USERS.containsKey(u))
                .findFirst()
                .ifPresent(u -> data.put("watchlist.user", WATCH_USERS.get(u)));

        data.put("spanMs", String.valueOf(alert.lastEventTimeMs() - alert.firstEventTimeMs()));
        return Map.copyOf(data);
    }
}
