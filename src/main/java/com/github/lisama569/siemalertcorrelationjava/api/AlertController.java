package com.github.lisama569.siemalertcorrelationjava.api;

import com.github.lisama569.siemalertcorrelationjava.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.alert.AlertStatus;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionError;
import com.github.lisama569.siemalertcorrelationjava.alert.TransitionResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 告警查询与处置 HTTP 入口。
 *
 * <p>结果区分：
 * <ul>
 *   <li>200 —— 查询成功 / 处置成功；</li>
 *   <li>404 —— 告警不存在（ALERT_NOT_FOUND）；</li>
 *   <li>409 —— 状态冲突（ILLEGAL_TRANSITION / ALREADY_TERMINAL / VERSION_CONFLICT）。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @GetMapping
    public List<AlertView> list() {
        return alertService.list().stream().map(AlertView::from).toList();
    }

    @GetMapping("/{alertId}")
    public ResponseEntity<?> get(@PathVariable String alertId) {
        return alertService.find(alertId)
                .<ResponseEntity<?>>map(alert -> ResponseEntity.ok(AlertView.from(alert)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorResponse("ALERT_NOT_FOUND", "告警不存在: " + alertId)));
    }

    @PostMapping("/{alertId}/acknowledge")
    public ResponseEntity<TransitionResponse> acknowledge(@PathVariable String alertId,
                                                          @RequestBody TransitionRequest req) {
        return doTransition(alertId, AlertStatus.ACKNOWLEDGED, req);
    }

    @PostMapping("/{alertId}/suppress")
    public ResponseEntity<TransitionResponse> suppress(@PathVariable String alertId,
                                                       @RequestBody TransitionRequest req) {
        return doTransition(alertId, AlertStatus.SUPPRESSED, req);
    }

    @PostMapping("/{alertId}/close")
    public ResponseEntity<TransitionResponse> close(@PathVariable String alertId,
                                                    @RequestBody TransitionRequest req) {
        return doTransition(alertId, AlertStatus.CLOSED, req);
    }

    private ResponseEntity<TransitionResponse> doTransition(String alertId, AlertStatus target,
                                                            TransitionRequest req) {
        String operator = req != null && req.operator() != null ? req.operator() : "anonymous";
        String note = req != null && req.note() != null ? req.note() : "";
        Long expectedVersion = req != null ? req.expectedVersion() : null;

        TransitionResult result = alertService.transition(
                alertId, target, operator, note, expectedVersion);
        if (result instanceof TransitionResult.Success s) {
            return ResponseEntity.ok(TransitionResponse.success(AlertView.from(s.alert())));
        }
        TransitionResult.Rejected r = (TransitionResult.Rejected) result;
        HttpStatus status = r.error() == TransitionError.ALERT_NOT_FOUND
                ? HttpStatus.NOT_FOUND : HttpStatus.CONFLICT;
        return ResponseEntity.status(status)
                .body(TransitionResponse.rejected(r.error().name(), r.detail()));
    }
}
