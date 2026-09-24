package com.github.lisama569.siemalertcorrelationjava.simulator;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionResult;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionResult;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.rule.RuleRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 本地事件流模拟器：演示 接入 -> 检测 -> 告警处置 的完整流程。
 *
 * <p>默认不启用；以 {@code mvn spring-boot:run -Dspring-boot.run.jvmArguments=-Ddemo.enabled=true}
 * 启动即可在本地复现整个流程，不依赖任何外部服务。
 */
@Component
@ConditionalOnProperty(name = "demo.enabled", havingValue = "true")
public class DemoRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoRunner.class);

    @Override
    public void run(String... args) {
        RuleRegistry registry = new RuleRegistry();
        registry.register(new RuleDefinition(
                "brute-force-login", 1, "同一账号 5 分钟内登录失败 >= 3 次",
                EventType.LOGIN_FAILED, "user",
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3));

        IngestionService ingestion = new IngestionService();
        AlertService alertService = new AlertService();
        DetectionEngine engine = new DetectionEngine(registry, alertService,
                java.time.Clock.systemUTC(),
                Map.of("alice", "HIGH"));

        // 构造本地事件流：乱序到达(彼此间隔 20s，在 1min 乱序容忍范围内) + 重复 + 非法记录
        List<RawEvent> stream = new ArrayList<>();
        stream.add(raw("e3", "auth-gateway", "LOGIN_FAILED", "2026-09-24T08:00:40Z", "alice"));
        stream.add(raw("e1", "auth-gateway", "LOGIN_FAILED", "2026-09-24T08:00:00Z", "alice"));
        stream.add(raw("e2", "auth-gateway", "LOGIN_FAILED", "2026-09-24T08:00:20Z", "alice"));
        stream.add(raw("e2", "auth-gateway", "LOGIN_FAILED", "2026-09-24T08:00:20Z", "alice")); // 重复
        // 乱序超容忍：08:05:00 的事件先推进水位线，随后 08:00:05 的迟到事件必须被明确丢弃
        stream.add(raw("e5", "auth-gateway", "LOGIN_FAILED", "2026-09-24T08:05:00Z", "bob"));
        stream.add(raw("e6", "auth-gateway", "LOGIN_FAILED", "2026-09-24T08:00:05Z", "bob"));
        stream.add(new RawEvent("e4", "auth-gateway", "NOT_A_TYPE",
                "2026-09-24T08:00:50Z", Map.of("user", "alice"))); // 非法类型
        stream.add(new RawEvent("", "auth-gateway", "LOGIN_FAILED",
                "2026-09-24T08:00:55Z", Map.of("user", "alice"))); // 缺 eventId

        log.info("==== 1. 接入与归一化 ====");
        List<com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent> accepted = new ArrayList<>();
        for (RawEvent raw : stream) {
            IngestResult result = ingestion.ingest(raw);
            log.info("ingest eventId={} -> {}", raw.eventId(), result);
            if (result instanceof IngestResult.Accepted a) {
                accepted.add(a.event());
            }
        }

        log.info("==== 2. 窗口检测 ====");
        DetectionResult detection = engine.evaluate(accepted);
        detection.notes().forEach(n -> log.info("note: {}", n));
        detection.newAlerts().forEach(a -> log.info("new alert: {}", a));

        log.info("==== 3. 告警处置 ====");
        for (Alert alert : alertService.list()) {
            TransitionResult r1 = alertService.acknowledge(alert.getAlertId(), "analyst-1", "已确认，排查中");
            log.info("ack {} -> {}", alert.getAlertId(), r1);
            TransitionResult r2 = alertService.close(alert.getAlertId(), "analyst-1", "误报，关闭");
            log.info("close {} -> {}", alert.getAlertId(), r2);
            TransitionResult r3 = alertService.acknowledge(alert.getAlertId(), "analyst-2", "尝试再次确认");
            log.info("re-ack {} -> {}", alert.getAlertId(), r3);
            alertService.find(alert.getAlertId()).ifPresent(a -> {
                log.info("final: {}", a);
                a.getHistory().forEach(h -> log.info("  history: {}", h));
            });
        }
    }

    private static RawEvent raw(String id, String source, String type, String at, String user) {
        return new RawEvent(id, source, type, at, Map.of("user", user));
    }
}
