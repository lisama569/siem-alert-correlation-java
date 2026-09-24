package com.github.lisama569.siemalertcorrelationjava.web;

import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleRegistry;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 规则注册与查询接口（规则按版本不可变）。 */
@RestController
@RequestMapping("/api/rules")
public class RuleController {

    private final RuleRegistry registry;

    public RuleController(RuleRegistry registry) {
        this.registry = registry;
    }

    @GetMapping
    public ResponseEntity<?> list() {
        return ResponseEntity.ok(registry.latestVersions());
    }

    @PostMapping
    public ResponseEntity<?> register(@RequestBody RuleDefinition rule) {
        try {
            registry.register(rule);
        } catch (IllegalArgumentException e) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("success", false);
            body.put("code", "R301");
            body.put("message", e.getMessage());
            return ResponseEntity.unprocessableEntity().body(body);
        }
        return ResponseEntity.ok(Map.of("success", true, "ruleKey", rule.key()));
    }
}
