package com.github.lisama569.siemalertcorrelationjava.config;

import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleRegistry;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.rule.CorrelationField;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

/**
 * 内置检测规则（容器初始化时即注册，早于任何 CommandLineRunner，避免执行顺序依赖）：
 * <ul>
 *   <li>R-BRUTE-FORCE v1/v2：同一用户 60s 窗口内 5 次（旧）/ 3 次（新）登录失败；</li>
 *   <li>R-C2-BEACON：同一源 IP 命中 2 次恶意软件检测；</li>
 *   <li>R-SCAN：同一源 IP 120s 内 4 次防火墙拦截。</li>
 * </ul>
 * v1 保留不删，可随时按版本重放历史；生效版本始终是最高版本。
 */
@Configuration
public class BuiltInRules {

    private static final Logger log = LoggerFactory.getLogger(BuiltInRules.class);

    static final long SECOND = 1000L;

    private final RuleRegistry registry;

    public BuiltInRules(RuleRegistry registry) {
        this.registry = registry;
    }

    @PostConstruct
    void register() {
        registry.register(RuleDefinition.of(
                "R-BRUTE-FORCE", "v1", "登录暴力破解(旧:5次)",
                EventType.LOGIN_FAILED, CorrelationField.USER,
                5, 60 * SECOND, 5 * SECOND, 15 * SECOND, "HIGH"));
        registry.register(RuleDefinition.of(
                "R-BRUTE-FORCE", "v2", "登录暴力破解(新:3次)",
                EventType.LOGIN_FAILED, CorrelationField.USER,
                3, 60 * SECOND, 5 * SECOND, 15 * SECOND, "HIGH"));
        registry.register(RuleDefinition.of(
                "R-C2-BEACON", "v1", "恶意软件检出(C2)",
                EventType.MALWARE_DETECTED, CorrelationField.SRC_IP,
                2, 120 * SECOND, 10 * SECOND, 60 * SECOND, "CRITICAL"));
        registry.register(RuleDefinition.of(
                "R-SCAN", "v1", "端口/主机扫描",
                EventType.FIREWALL_BLOCK, CorrelationField.SRC_IP,
                4, 120 * SECOND, 10 * SECOND, 30 * SECOND, "MEDIUM"));
        log.info("内置规则注册完成，共 {} 个版本", registry.size());
    }
}
