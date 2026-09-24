package com.github.lisama569.siemalertcorrelationjava.web;

import com.github.lisama569.siemalertcorrelationjava.engine.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertAction;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertCommand;
import com.github.lisama569.siemalertcorrelationjava.model.alert.CommandResult;
import com.github.lisama569.siemalertcorrelationjava.model.alert.TransitionFailure;
import com.github.lisama569.siemalertcorrelationjava.web.dto.ActionRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 告警查询与生命周期处置接口。 */
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @GetMapping
    public ResponseEntity<?> list() {
        return ResponseEntity.ok(alertService.list().stream().map(AlertController::toView).toList());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable String id) {
        return alertService.get(id)
                .<ResponseEntity<?>>map(a -> ResponseEntity.ok(toView(a)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("success", false, "code", TransitionFailure.ALERT_NOT_FOUND.code(),
                                "message", "告警不存在: " + id)));
    }

    @PostMapping("/{id}/actions")
    public ResponseEntity<?> act(@PathVariable String id, @RequestBody ActionRequest request) {
        AlertAction action;
        try {
            action = AlertAction.valueOf(request.action() == null ? "" : request.action().trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false, "code", TransitionFailure.INVALID_PAYLOAD.code(),
                    "message", "未知动作: " + request.action()));
        }
        CommandResult result = alertService.apply(
                new AlertCommand(id, action, request.actor(), request.reason(), request.expectedVersion()));
        if (result.success()) {
            return ResponseEntity.ok(toView(result.alert()));
        }
        HttpStatus status = result.failure() == TransitionFailure.ALERT_NOT_FOUND
                ? HttpStatus.NOT_FOUND
                : result.failure() == TransitionFailure.VERSION_CONFLICT
                        ? HttpStatus.CONFLICT : HttpStatus.UNPROCESSABLE_ENTITY;
        return ResponseEntity.status(status).body(Map.of(
                "success", false,
                "code", result.failure().code(),
                "reason", result.failure().name(),
                "detail", result.detail() == null ? "" : result.detail(),
                "currentVersion", result.alert() == null ? -1 : result.alert().version(),
                "currentState", result.alert() == null ? "" : result.alert().state().name()));
    }

    static Map<String, Object> toView(Alert a) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("alertId", a.alertId());
        view.put("fingerprint", a.fingerprint());
        view.put("ruleId", a.ruleId());
        view.put("ruleVersion", a.ruleVersion());
        view.put("correlationKey", a.correlationKey());
        view.put("state", a.state());
        view.put("version", a.version());
        view.put("severity", a.severity());
        view.put("eventCount", a.eventCount());
        view.put("enrichment", a.enrichment());
        view.put("auditTrail", a.auditTrail());
        return view;
    }
}
