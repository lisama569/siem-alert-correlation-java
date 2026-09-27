package com.github.lisama569.siemalertcorrelationjava;

import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;

/**
 * 本地检测链路装配：规则注册表 -> 接入 -> 检测 -> 告警。
 *
 * <p>全部为纯内存实现，不依赖任何外部服务或真实凭据；
 * 默认注册与演示一致的暴力破解检测规则（v1）。
 */
@Configuration
public class PipelineConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public RuleRegistry ruleRegistry() {
        RuleRegistry registry = new RuleRegistry();
        registry.register(new RuleDefinition(
                "brute-force-login", 1, "同一账号 5 分钟内登录失败 >= 3 次",
                EventType.LOGIN_FAILED, "user",
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3));
        return registry;
    }

    @Bean
    public IngestionService ingestionService(Clock clock) {
        return new IngestionService(clock);
    }

    @Bean
    public AlertService alertService(Clock clock) {
        return new AlertService(clock);
    }

    @Bean
    public DetectionEngine detectionEngine(RuleRegistry registry, AlertService alertService,
                                           Clock clock) {
        return new DetectionEngine(registry, alertService, clock);
    }
}
