package com.github.lisama569.siemalertcorrelationjava.web;

import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.pipeline.DetectionPipeline;
import com.github.lisama569.siemalertcorrelationjava.web.dto.EventRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 事件接入接口：归一化、去重、检测、告警一条龙。 */
@RestController
@RequestMapping("/api/events")
public class EventController {

    private final DetectionPipeline pipeline;

    public EventController(DetectionPipeline pipeline) {
        this.pipeline = pipeline;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> submit(@RequestBody EventRequest request) {
        RawEvent raw = new RawEvent(request.source(), request.type(), request.eventTime(),
                request.rawId(), request.user(), request.srcIp(), request.dstIp(),
                request.host(), request.attributes());
        DetectionPipeline.PipelineResult result = pipeline.handle(raw);

        Map<String, Object> body = new LinkedHashMap<>();
        var ing = result.ingestion();
        if (!ing.accepted()) {
            body.put("success", false);
            body.put("code", ing.reason().code());
            body.put("reason", ing.reason().name());
            body.put("detail", ing.detail());
            return ResponseEntity.unprocessableEntity().body(body);
        }
        body.put("success", true);
        body.put("duplicate", ing.duplicate());
        body.put("eventId", ing.eventId());
        body.put("fires", result.fires().stream().map(f -> Map.of(
                "ruleKey", f.ruleKey(),
                "fired", f.fired(),
                "suppressedDuplicate", f.suppressedDuplicate(),
                "lateDecision", f.lateDecision().name(),
                "fingerprint", f.fingerprint() == null ? "" : f.fingerprint())).toList());
        body.put("alertIds", result.alerts().stream().map(a -> a.alertId()).toList());
        return ResponseEntity.ok(body);
    }
}
