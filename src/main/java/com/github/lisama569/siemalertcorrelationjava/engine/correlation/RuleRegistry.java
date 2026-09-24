package com.github.lisama569.siemalertcorrelationjava.engine.correlation;

import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 规则注册表。
 * 规则以 ruleId:version 作为不可变键存储：同一版本重复注册必须内容一致，否则拒绝；
 * 同 ruleId 下版本按字符串排序取最大值为生效版本。旧版本永不删除/覆盖，历史可复现。
 */
@Service
public class RuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(RuleRegistry.class);

    private final Map<String, RuleDefinition> rules = new ConcurrentHashMap<>();

    public synchronized void register(RuleDefinition rule) {
        if (rule == null || rule.ruleId() == null || rule.version() == null) {
            throw new IllegalArgumentException("规则及其 ruleId/version 不能为空");
        }
        RuleDefinition existing = rules.get(rule.key());
        if (existing != null && !existing.equals(rule)) {
            throw new IllegalArgumentException(
                    "规则版本不可变: " + rule.key() + " 已以不同内容注册");
        }
        if (existing == null) {
            rules.put(rule.key(), rule);
            log.info("规则已注册 {} ({}), threshold={}, windowMs={}, latenessMs={}",
                    rule.key(), rule.name(), rule.threshold(), rule.windowMs(), rule.allowedLatenessMs());
        }
    }

    public Optional<RuleDefinition> get(String ruleId, String version) {
        return Optional.ofNullable(rules.get(ruleId + ":" + version));
    }

    /** 同 ruleId 下版本字符串最大者视为最新版本（v1 &lt; v2 &lt; v10）。 */
    public Optional<RuleDefinition> latest(String ruleId) {
        return rules.values().stream()
                .filter(r -> r.ruleId().equals(ruleId))
                .max(Comparator.comparing(RuleDefinition::version));
    }

    /** 每个 ruleId 的最新版本列表。 */
    public List<RuleDefinition> latestVersions() {
        return rules.values().stream()
                .collect(java.util.stream.Collectors.groupingBy(RuleDefinition::ruleId))
                .values().stream()
                .map(list -> list.stream()
                        .max(Comparator.comparing(RuleDefinition::version)).orElseThrow())
                .toList();
    }

    public int size() {
        return rules.size();
    }
}
