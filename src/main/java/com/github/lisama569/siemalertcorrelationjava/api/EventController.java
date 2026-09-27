package com.github.lisama569.siemalertcorrelationjava.api;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionEngine;
import com.github.lisama569.siemalertcorrelationjava.detection.DetectionResult;
import com.github.lisama569.siemalertcorrelationjava.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * 事件接入 HTTP 入口。
 *
 * <p>结果区分（单条）：
 * <ul>
 *   <li>201 ACCEPTED —— 校验通过并受理，进入检测；</li>
 *   <li>200 DUPLICATE —— 重复提交，幂等返回，不重复计数；</li>
 *   <li>422 REJECTED —— 校验拒绝，响应体携带具体 reason。</li>
 * </ul>
 * 批量接口整体返回 200，逐条结果在 items 中按上述三态区分。
 */
@RestController
@RequestMapping("/api/events")
public class EventController {

    private final IngestionService ingestionService;
    private final DetectionEngine detectionEngine;

    public EventController(IngestionService ingestionService, DetectionEngine detectionEngine) {
        this.ingestionService = ingestionService;
        this.detectionEngine = detectionEngine;
    }

    @PostMapping
    public ResponseEntity<IngestResponse> ingestOne(@RequestBody RawEvent raw) {
        IngestResult result = ingestionService.ingest(raw);
        if (result instanceof IngestResult.Accepted a) {
            DetectionResult detection = detectionEngine.evaluate(List.of(a.event()));
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(IngestResponse.accepted(a.event().eventId(), alertIds(detection)));
        }
        if (result instanceof IngestResult.Duplicate d) {
            return ResponseEntity.ok(IngestResponse.duplicate(d.eventId()));
        }
        IngestResult.Rejected r = (IngestResult.Rejected) result;
        return ResponseEntity.unprocessableEntity()
                .body(IngestResponse.rejected(raw.eventId(), r.reason().name(), r.detail()));
    }

    @PostMapping("/batch")
    public BatchIngestResponse ingestBatch(@RequestBody List<RawEvent> raws) {
        List<IngestResponse> items = new ArrayList<>(raws.size());
        List<SecurityEvent> acceptedEvents = new ArrayList<>();
        int accepted = 0;
        int duplicates = 0;
        int rejected = 0;
        for (RawEvent raw : raws) {
            IngestResult result = ingestionService.ingest(raw);
            if (result instanceof IngestResult.Accepted a) {
                accepted++;
                acceptedEvents.add(a.event());
                // 告警 ID 在整批检测后统一汇总，单项先占位
                items.add(IngestResponse.accepted(a.event().eventId(), List.of()));
            } else if (result instanceof IngestResult.Duplicate d) {
                duplicates++;
                items.add(IngestResponse.duplicate(d.eventId()));
            } else {
                rejected++;
                IngestResult.Rejected r = (IngestResult.Rejected) result;
                items.add(IngestResponse.rejected(
                        raw.eventId(), r.reason().name(), r.detail()));
            }
        }
        // 整批一次性进入检测，保证窗口计数与逐条提交一致
        DetectionResult detection = detectionEngine.evaluate(acceptedEvents);
        return new BatchIngestResponse(raws.size(), accepted, duplicates, rejected,
                items, alertIds(detection));
    }

    private static List<String> alertIds(DetectionResult detection) {
        return detection.newAlerts().stream().map(Alert::getAlertId).toList();
    }
}
