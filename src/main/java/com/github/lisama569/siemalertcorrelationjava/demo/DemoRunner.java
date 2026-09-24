package com.github.lisama569.siemalertcorrelationjava.demo;

import com.github.lisama569.siemalertcorrelationjava.engine.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleRegistry;
import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleReplayer;
import com.github.lisama569.siemalertcorrelationjava.engine.ingest.EventNormalizer;
import com.github.lisama569.siemalertcorrelationjava.engine.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertAction;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertCommand;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertState;
import com.github.lisama569.siemalertcorrelationjava.model.alert.CommandResult;
import com.github.lisama569.siemalertcorrelationjava.model.event.IngestionOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.ReplayReport;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.pipeline.DetectionPipeline;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * 本地演示运行器。消费 {@link DemoScenario} 的事件流，逐条打印输入、关键判定依据与最终状态，
 * 随后执行并发处置演示与规则版本重放演示。仅在 app.demo.enabled=true 时运行。
 */
@Component
@ConditionalOnProperty(name = "app.demo.enabled", havingValue = "true")
public class DemoRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger("SIEM-DEMO");

    private final DetectionPipeline pipeline;
    private final IngestionService ingestionService;
    private final EventNormalizer normalizer;
    private final AlertService alertService;
    private final RuleRegistry registry;
    private final RuleReplayer replayer;

    public DemoRunner(DetectionPipeline pipeline, IngestionService ingestionService,
                      EventNormalizer normalizer, AlertService alertService,
                      RuleRegistry registry, RuleReplayer replayer) {
        this.pipeline = pipeline;
        this.ingestionService = ingestionService;
        this.normalizer = normalizer;
        this.alertService = alertService;
        this.registry = registry;
        this.replayer = replayer;
    }

    @Override
    public void run(String... args) {
        log.info("================ 本地威胁检测与告警关联演示 ================");
        int rejected = 0;
        int duplicate = 0;
        List<SecurityEvent> acceptedEvents = new ArrayList<>();

        for (RawEvent raw : DemoScenario.events()) {
            long now = System.currentTimeMillis();
            IngestionOutcome pre = normalizer.normalize(raw, now);
            log.info("[输入] rawId={} source={} type={} eventTime={} user={} srcIp={}",
                    raw.rawId(), raw.source(), raw.type(), raw.eventTime(), raw.user(), raw.srcIp());

            DetectionPipeline.PipelineResult result = pipeline.handle(raw);
            IngestionOutcome ing = result.ingestion();
            if (!ing.accepted()) {
                rejected++;
                log.info("[拒绝] code={} reason={} detail={}",
                        ing.reason().code(), ing.reason(), ing.detail());
            } else if (ing.duplicate()) {
                duplicate++;
                log.info("[重复] eventId={} 不重复计数、不进入检测", ing.eventId());
            } else {
                acceptedEvents.add(ing.event());
                result.fires().forEach(f -> {
                    if (f.fired()) {
                        log.info("[触发] rule={} key={} fingerprint={} late={} 贡献事件={}",
                                f.ruleKey(), f.correlationKey(), f.fingerprint(),
                                f.lateDecision(), f.contributingEvents().size());
                    } else {
                        log.info("[判定] rule={} fired=false late={} suppressed={} watermark={}",
                                f.ruleKey(), f.lateDecision(), f.suppressedDuplicate(), f.watermarkMs());
                    }
                });
                result.alerts().forEach(a -> log.info("[告警] id={} state={} 富化={}",
                        a.alertId(), a.state(), a.enrichment()));
            }
        }

        log.info("---- 接入汇总：接受(唯一)={} 重复={} 拒绝={} ----",
                ingestionService.acceptedCount(), duplicate, rejected);

        log.info("================ 告警最终状态（处置前） ================");
        alertService.list().forEach(a -> log.info("[最终状态] {} {} {} eventCount={} state={}",
                a.alertId(), a.ruleId(), a.severity(), a.eventCount(), a.state()));

        runConcurrentTransitions();
        runVersionReplay(acceptedEvents);

        log.info("================ 演示期望核对 ================");
        DemoScenario.expectations().forEach(e -> log.info("[期望 {}] {}", e.code(), e.description()));
        log.info("================ 演示结束 ================");
    }

    /** 并发确认/抑制/关闭：同一告警 3 个动作并发提交，最终状态必须确定且审计链完整。 */
    private void runConcurrentTransitions() {
        alertService.list().stream()
                .filter(a -> a.ruleId().equals("R-BRUTE-FORCE"))
                .findFirst()
                .ifPresent(alert -> {
                    log.info("---- 并发处置演示 alertId={} 起始 version={} state={} ----",
                            alert.alertId(), alert.version(), alert.state());
                    ExecutorService pool = Executors.newFixedThreadPool(3);
                    List<Future<CommandResult>> futures = List.of(
                            pool.submit(() -> alertService.apply(
                                    new AlertCommand(alert.alertId(), AlertAction.ACKNOWLEDGE,
                                            "analyst-1", "我来跟进", null))),
                            pool.submit(() -> alertService.apply(
                                    new AlertCommand(alert.alertId(), AlertAction.SUPPRESS,
                                            "analyst-2", "疑似误报，抑制", null))),
                            pool.submit(() -> alertService.apply(
                                    new AlertCommand(alert.alertId(), AlertAction.CLOSE,
                                            "analyst-3", "确认为已知事件，关闭", null))));
                    for (int i = 0; i < futures.size(); i++) {
                        try {
                            CommandResult r = futures.get(i).get(5, TimeUnit.SECONDS);
                            log.info("[并发结果 {}] success={} state={} code={}",
                                    i, r.success(),
                                    r.alert() == null ? null : r.alert().state(),
                                    r.failure() == null ? "-" : r.failure().code());
                        } catch (Exception e) {
                            log.warn("并发处置异常", e);
                        }
                    }
                    pool.shutdownNow();
                    Alert finalAlert = alertService.get(alert.alertId()).orElseThrow();
                    log.info("[并发后状态] state={} version={} 审计条数={}",
                            finalAlert.state(), finalAlert.version(), finalAlert.auditTrail().size());
                    finalAlert.auditTrail().forEach(a -> log.info(
                            "  审计#{} {} -> {} accepted={} code={} actor={} detail={}",
                            a.sequence(), a.fromState(), a.toState(), a.accepted(),
                            a.rejectionCode(), a.actor(), a.detail()));
                    if (finalAlert.state() != AlertState.CLOSED) {
                        log.warn("并发演示后状态非 CLOSED（取决于动作串行顺序），当前={}", finalAlert.state());
                    }
                });
    }

    /** 规则版本复现：同一历史序列分别用 v1/v2 重放，结论应稳定可复现且互不污染。 */
    private void runVersionReplay(List<SecurityEvent> events) {
        var v1Opt = registry.get("R-BRUTE-FORCE", "v1");
        var v2Opt = registry.get("R-BRUTE-FORCE", "v2");
        if (v1Opt.isEmpty() || v2Opt.isEmpty()) {
            log.warn("内置规则未就绪，跳过版本重放演示");
            return;
        }
        RuleDefinition v1 = v1Opt.get();
        RuleDefinition v2 = v2Opt.get();
        List<SecurityEvent> loginFailures = events.stream()
                .filter(e -> e.type().name().equals("LOGIN_FAILED"))
                .toList();

        ReplayReport r1 = replayer.replay(v1, loginFailures);
        ReplayReport r2a = replayer.replay(v2, loginFailures);
        ReplayReport r2b = replayer.replay(v2, loginFailures);
        log.info("---- 规则版本重放 ----");
        log.info("[重放 v1 阈值5] 触发={} 重复抑制={} 过迟丢弃={}",
                r1.firedCount(), r1.duplicateCount(), r1.rejectedLateCount());
        log.info("[重放 v2 阈值3 第一次] 触发={} 指纹={}", r2a.firedCount(), r2a.fingerprints());
        log.info("[重放 v2 阈值3 第二次] 触发={} 指纹={} 两次一致={}",
                r2b.firedCount(), r2b.fingerprints(), r2a.fingerprints().equals(r2b.fingerprints()));
    }
}
