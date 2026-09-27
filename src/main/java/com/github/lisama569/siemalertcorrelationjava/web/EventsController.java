package com.github.lisama569.siemalertcorrelationjava.web;

import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.pipeline.EventPipeline;
import com.github.lisama569.siemalertcorrelationjava.web.dto.BatchEventRequest;
import com.github.lisama569.siemalertcorrelationjava.web.dto.BatchResult;
import com.github.lisama569.siemalertcorrelationjava.web.dto.EventRequest;
import com.github.lisama569.siemalertcorrelationjava.web.dto.ItemResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 事件接入 HTTP 入口（仅监听本机，全部本地处理）。
 *
 * <p>结果区分（单条）：
 * <ul>
 *   <li>{@code 200} + ACCEPTED：正常受理；</li>
 *   <li>{@code 409} + DUPLICATE：重复提交，未重复计数/告警；</li>
 *   <li>{@code 422} + REJECTED：被拒绝，{@code reason} 给出具体拒绝原因；</li>
 *   <li>{@code 400}：请求体本身非法（如空事件）。</li>
 * </ul>
 * 批量接口固定 {@code 200}，逐条结果携带各自 outcome/reason。
 */
@RestController
@RequestMapping("/api/events")
public class EventsController {

    private final EventPipeline pipeline;

    public EventsController(EventPipeline pipeline) {
        this.pipeline = pipeline;
    }

    @PostMapping
    public ResponseEntity<ItemResult> submit(@RequestBody EventRequest request) {
        if (request == null) {
            return ResponseEntity.badRequest()
                    .body(new ItemResult("REJECTED", null, "EMPTY_BODY", "请求体为空"));
        }
        RawEvent raw = WebViews.toRaw(request);
        IngestResult result = pipeline.submit(raw);
        ItemResult view = WebViews.item(request, result);
        return switch (view.outcome()) {
            case "ACCEPTED" -> ResponseEntity.ok(view);
            case "DUPLICATE" -> ResponseEntity.status(409).body(view);
            default -> ResponseEntity.unprocessableEntity().body(view);
        };
    }

    @PostMapping("/batch")
    public ResponseEntity<BatchResult> submitBatch(@RequestBody BatchEventRequest request) {
        if (request == null || request.events() == null || request.events().isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        List<RawEvent> raws = request.events().stream().map(WebViews::toRaw).toList();
        List<IngestResult> outcomes = pipeline.submitAll(raws);

        int accepted = 0;
        int duplicate = 0;
        int rejected = 0;
        var items = new java.util.ArrayList<ItemResult>(request.events().size());
        for (int i = 0; i < request.events().size(); i++) {
            ItemResult item = WebViews.item(request.events().get(i), outcomes.get(i));
            items.add(item);
            switch (item.outcome()) {
                case "ACCEPTED" -> accepted++;
                case "DUPLICATE" -> duplicate++;
                default -> rejected++;
            }
        }
        return ResponseEntity.ok(new BatchResult(
                request.events().size(), accepted, duplicate, rejected,
                List.copyOf(items)));
    }

    /** 便捷：GET 当前受认可来源，方便运营核对。 */
    @org.springframework.web.bind.annotation.GetMapping("/allowed-sources")
    public Map<String, Object> allowedSources() {
        return Map.of("allowedSources", pipeline.ingestion().allowedSources());
    }
}
