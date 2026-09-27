package com.github.lisama569.siemalertcorrelationjava.web;

import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertStatus;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionError;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionResult;
import com.github.lisama569.siemalertcorrelationjava.pipeline.EventPipeline;
import com.github.lisama569.siemalertcorrelationjava.web.dto.AlertView;
import com.github.lisama569.siemalertcorrelationjava.web.dto.ApiError;
import com.github.lisama569.siemalertcorrelationjava.web.dto.TransitionRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;
import java.util.Map;

/**
 * 告警查询与处置 HTTP 入口（仅本机）。
 *
 * <p>结果区分：
 * <ul>
 *   <li>{@code 200}：查询成功 / 处置成功（响应含处置后快照，version 连续递增）；</li>
 *   <li>{@code 404} + {@code ALERT_NOT_FOUND}：按编号查不到告警；</li>
 *   <li>{@code 409} + 冲突原因：{@code ILLEGAL_TRANSITION} / {@code ALREADY_TERMINAL}
 *       / {@code VERSION_CONFLICT}，调用方可据此区分各类状态冲突；</li>
 *   <li>{@code 400}：action 非法或请求体无法解析。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertsController {

    private final EventPipeline pipeline;

    public AlertsController(EventPipeline pipeline) {
        this.pipeline = pipeline;
    }

    @GetMapping("/{alertId}")
    public ResponseEntity<?> get(@PathVariable String alertId) {
        return pipeline.alertService().find(alertId)
                .<ResponseEntity<?>>map(a -> ResponseEntity.ok(WebViews.alertView(a)))
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ApiError(TransitionError.ALERT_NOT_FOUND.name(),
                                "告警不存在: " + alertId)));
    }

    @GetMapping
    public Map<String, Object> list() {
        return Map.of("alerts", pipeline.alertService().list().stream()
                .map(WebViews::alertView).toList());
    }

    /**
     * 对告警发起处置。action 取 URL 路径段：acknowledge / suppress / close。
     * 请求体可空，可携带 operator、note 与可选 expectedVersion（乐观锁）。
     */
    @PostMapping("/{alertId}/{action}")
    public ResponseEntity<?> transition(@PathVariable String alertId,
                                        @PathVariable String action,
                                        @RequestBody(required = false) TransitionRequest request) {
        AlertStatus target = mapAction(action);
        if (target == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiError("INVALID_ACTION",
                            "未知处置动作: " + action
                                    + "（支持 acknowledge / suppress / close）"));
        }
        String operator = request != null && request.operator() != null && !request.operator().isBlank()
                ? request.operator() : "anonymous";
        String note = request != null && request.note() != null ? request.note() : "";
        Long expectedVersion = request != null ? request.expectedVersion() : null;

        TransitionResult result = pipeline.alertService()
                .transition(alertId, target, operator, note, expectedVersion);
        if (result instanceof TransitionResult.Success s) {
            return ResponseEntity.ok(Map.of(
                    "outcome", "APPLIED",
                    "alert", WebViews.alertView(s.alert())));
        }
        TransitionResult.Rejected rejected = (TransitionResult.Rejected) result;
        int status = rejected.error() == TransitionError.ALERT_NOT_FOUND ? 404 : 409;
        return ResponseEntity.status(status)
                .body(new ApiError(rejected.error().name(), rejected.detail()));
    }

    private static AlertStatus mapAction(String action) {
        if (action == null) {
            return null;
        }
        return switch (action.trim().toLowerCase(Locale.ROOT)) {
            case "acknowledge", "ack" -> AlertStatus.ACKNOWLEDGED;
            case "suppress" -> AlertStatus.SUPPRESSED;
            case "close" -> AlertStatus.CLOSED;
            default -> null;
        };
    }

    /** 暴露给测试/运行期使用的服务句柄。 */
    AlertService alertService() {
        return pipeline.alertService();
    }
}
