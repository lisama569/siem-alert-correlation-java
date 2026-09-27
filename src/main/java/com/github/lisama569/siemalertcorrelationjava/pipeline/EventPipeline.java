package com.github.lisama569.siemalertcorrelationjava.pipeline;

import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * 本地事件处理管线：接入（校验+去重）→ 窗口关联检测。
 *
 * <p>被拒绝与重复提交的事件不进入检测；接受的事件立即送入检测引擎。
 * 检测引擎 {@code evaluate} 自身为 {@code synchronized}，因此多线程并发提交时
 * 窗口计数与告警触发仍然串行化、确定且不重复。
 */
public class EventPipeline {

    private final IngestionService ingestion;
    private final DetectionEngine engine;
    private final AlertService alertService;

    public EventPipeline(IngestionService ingestion, DetectionEngine engine,
                         AlertService alertService) {
        this.ingestion = ingestion;
        this.engine = engine;
        this.alertService = alertService;
    }

    /** 提交一条原始事件，返回接入结果；接受时同步完成检测。 */
    public IngestResult submit(RawEvent raw) {
        IngestResult result = ingestion.ingest(raw);
        if (result instanceof IngestResult.Accepted accepted) {
            engine.evaluate(List.of(accepted.event()));
        }
        return result;
    }

    /** 批量提交：逐条接入并保持批次内顺序，返回每条事件的接入结果。 */
    public List<IngestResult> submitAll(List<RawEvent> raws) {
        List<IngestResult> results = new ArrayList<>(raws.size());
        List<SecurityEvent> accepted = new ArrayList<>();
        for (RawEvent raw : raws) {
            IngestResult result = ingestion.ingest(raw);
            results.add(result);
            if (result instanceof IngestResult.Accepted a) {
                accepted.add(a.event());
            }
        }
        // 本批接受的事件一次性按序评估（引擎内会再按事件时间排序，乱序也确定）
        if (!accepted.isEmpty()) {
            engine.evaluate(accepted);
        }
        return results;
    }

    public IngestionService ingestion() {
        return ingestion;
    }

    public DetectionEngine engine() {
        return engine;
    }

    public AlertService alertService() {
        return alertService;
    }
}
