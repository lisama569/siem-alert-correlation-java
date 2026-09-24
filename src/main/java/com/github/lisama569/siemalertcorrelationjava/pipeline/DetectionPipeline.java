package com.github.lisama569.siemalertcorrelationjava.pipeline;

import com.github.lisama569.siemalertcorrelationjava.engine.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.engine.correlation.CorrelationEngine;
import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleRegistry;
import com.github.lisama569.siemalertcorrelationjava.engine.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.event.IngestionOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.FireOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 检测流水线：接入归一化 → 确定性去重 → 多规则关联检测 → 告警幂等创建/富化。
 * 被拒绝或重复的事件不会进入检测；同一规则条件（指纹）最多产生一个告警。
 */
@Service
public class DetectionPipeline {

    private static final Logger log = LoggerFactory.getLogger(DetectionPipeline.class);

    private final IngestionService ingestionService;
    private final CorrelationEngine correlationEngine;
    private final AlertService alertService;
    private final RuleRegistry registry;
    private final Clock clock;

    public DetectionPipeline(IngestionService ingestionService,
                             CorrelationEngine correlationEngine,
                             AlertService alertService,
                             RuleRegistry registry,
                             Clock clock) {
        this.ingestionService = ingestionService;
        this.correlationEngine = correlationEngine;
        this.alertService = alertService;
        this.registry = registry;
        this.clock = clock;
    }

    public PipelineResult handle(RawEvent raw) {
        IngestionOutcome ingestion = ingestionService.ingest(raw);
        if (!ingestion.accepted()) {
            log.info("流水线：事件被拒绝 code={} reason={} detail={}",
                    ingestion.reason().code(), ingestion.reason(), ingestion.detail());
            return new PipelineResult(ingestion, List.of(), List.of());
        }
        if (ingestion.duplicate()) {
            log.info("流水线：重复事件 eventId={}，跳过检测（不重复计数/告警）", ingestion.eventId());
            return new PipelineResult(ingestion, List.of(), List.of());
        }

        List<FireOutcome> fires = correlationEngine.process(ingestion.event(), clock.millis());
        List<Alert> alerts = new ArrayList<>();
        for (FireOutcome fire : fires) {
            if (!fire.fired()) {
                if (fire.lateDecision() != null) {
                    log.debug("流水线：规则未触发 ruleKey={} late={} suppressed={}",
                            fire.ruleKey(), fire.lateDecision(), fire.suppressedDuplicate());
                }
                continue;
            }
            RuleDefinition rule = registry.get(ruleIdOf(fire.ruleKey()), versionOf(fire.ruleKey()))
                    .orElseThrow(() -> new IllegalStateException("规则已注册却无法读取: " + fire.ruleKey()));
            Alert alert = alertService.createIfAbsent(fire, new AlertService.RuleContext(
                    rule.ruleId(), rule.version(), rule.name(), rule.severity(),
                    rule.windowMs(), rule.allowedLatenessMs()));
            alerts.add(alert);
            log.info("流水线：新告警 alertId={} state={} fingerprint={}",
                    alert.alertId(), alert.state(), alert.fingerprint());
        }
        return new PipelineResult(ingestion, List.copyOf(fires), List.copyOf(alerts));
    }

    private static String ruleIdOf(String ruleKey) {
        int idx = ruleKey.lastIndexOf(':');
        return ruleKey.substring(0, idx);
    }

    private static String versionOf(String ruleKey) {
        int idx = ruleKey.lastIndexOf(':');
        return ruleKey.substring(idx + 1);
    }

    /** 一次流水线处理的完整结果（便于日志与测试断言）。 */
    public record PipelineResult(
            IngestionOutcome ingestion,
            List<FireOutcome> fires,
            List<Alert> alerts) {
    }
}
