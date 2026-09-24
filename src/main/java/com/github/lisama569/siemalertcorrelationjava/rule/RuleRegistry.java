package com.github.lisama569.siemalertcorrelationjava.rule;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 规则注册表：按规则 ID 保存全部历史版本。
 *
 * <p>版本号必须严格递增；历史版本永不被覆盖，因此任意时刻都可以取出规则在过去某个时刻的
 * 定义，用于复现历史判定结果（见 {@link #versionAt(String, int)}）。
 */
public class RuleRegistry {

    private final Map<String, CopyOnWriteArrayList<RuleDefinition>> rules = new ConcurrentHashMap<>();

    /** 注册一个新版本。版本号必须高于该规则已有的最高版本，否则拒绝。 */
    public RuleDefinition register(RuleDefinition rule) {
        CopyOnWriteArrayList<RuleDefinition> versions =
                rules.computeIfAbsent(rule.ruleId(), k -> new CopyOnWriteArrayList<>());
        synchronized (versions) {
            int max = versions.stream().mapToInt(RuleDefinition::version).max().orElse(0);
            if (rule.version() <= max) {
                throw new IllegalArgumentException(
                        "规则版本必须严格递增: ruleId=" + rule.ruleId()
                                + ", 提交版本=" + rule.version() + ", 当前最高版本=" + max);
            }
            versions.add(rule);
        }
        return rule;
    }

    public Optional<RuleDefinition> current(String ruleId) {
        CopyOnWriteArrayList<RuleDefinition> versions = rules.get(ruleId);
        if (versions == null || versions.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(versions.get(versions.size() - 1));
    }

    /** 取规则在历史时刻对应的版本：不大于 givenVersion 的最高版本。 */
    public Optional<RuleDefinition> versionAt(String ruleId, int givenVersion) {
        CopyOnWriteArrayList<RuleDefinition> versions = rules.get(ruleId);
        if (versions == null) {
            return Optional.empty();
        }
        RuleDefinition found = null;
        for (RuleDefinition r : versions) {
            if (r.version() <= givenVersion && (found == null || r.version() > found.version())) {
                found = r;
            }
        }
        return Optional.ofNullable(found);
    }

    public List<RuleDefinition> versions(String ruleId) {
        CopyOnWriteArrayList<RuleDefinition> versions = rules.get(ruleId);
        return versions == null ? List.of() : List.copyOf(versions);
    }

    /** 当前生效规则快照（ruleId -> 最新版本）。 */
    public Map<String, RuleDefinition> snapshot() {
        Map<String, RuleDefinition> snapshot = new java.util.HashMap<>();
        rules.forEach((id, versions) -> {
            if (!versions.isEmpty()) {
                snapshot.put(id, versions.get(versions.size() - 1));
            }
        });
        return Map.copyOf(snapshot);
    }
}
