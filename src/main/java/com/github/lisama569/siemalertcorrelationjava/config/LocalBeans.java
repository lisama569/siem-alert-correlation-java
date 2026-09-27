package com.github.lisama569.siemalertcorrelationjava.config;

import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.pipeline.EventPipeline;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;

/**
 * 本地组件装配：接入服务、规则注册表、检测引擎、告警服务与事件管线均为纯内存单例。
 * 骨架版本：仅保证 Bean 结构可装配，管线实现后续填充。
 */
@Configuration
public class LocalBeans {

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
    public AlertService alertService(Clock clock) {
        return new AlertService(clock);
    }

    @Bean
    public DetectionEngine detectionEngine(RuleRegistry registry, AlertService alertService,
                                           Clock clock) {
        return new DetectionEngine(registry, alertService, clock, Map.of("alice", "HIGH"));
    }

    @Bean
    public IngestionService ingestionService(Clock clock) {
        return new IngestionService(clock);
    }

    @Bean
    public EventPipeline eventPipeline(IngestionService ingestion, DetectionEngine engine,
                                       AlertService alertService) {
        return new EventPipeline(ingestion, engine, alertService);
    }
}
