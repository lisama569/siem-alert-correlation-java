package com.github.lisama569.siemalertcorrelationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.siemalertcorrelationjava.demo.DemoScenario;
import com.github.lisama569.siemalertcorrelationjava.engine.alert.AlertService;
import com.github.lisama569.siemalertcorrelationjava.engine.correlation.CorrelationEngine;
import com.github.lisama569.siemalertcorrelationjava.engine.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.model.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.model.alert.AlertState;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.pipeline.DetectionPipeline;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestLogger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/** 端到端：本地事件流全量跑通，结论与 HTTP 接口一致且可解释。 */
@SpringBootTest
@AutoConfigureMockMvc
class EndToEndPipelineTest {

    @Autowired private DetectionPipeline pipeline;
    @Autowired private IngestionService ingestionService;
    @Autowired private AlertService alertService;
    @Autowired private CorrelationEngine correlationEngine;
    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    /** 每个测试前清空运行期状态（规则保留），保证测试间互不污染、结论可复现。 */
    @BeforeEach
    void resetState() {
        ingestionService.reset();
        correlationEngine.reset();
        alertService.reset();
        // 统一灌入标准本地事件流，使三个测试从同一确定基线出发
        for (RawEvent raw : DemoScenario.events()) {
            pipeline.handle(raw);
        }
    }

    private Map<String, Object> body(RawEvent raw) {
        Map<String, Object> m = new HashMap<>();
        m.put("source", raw.source());
        m.put("type", raw.type());
        m.put("eventTime", raw.eventTime());
        m.put("rawId", raw.rawId());
        m.put("user", raw.user());
        m.put("srcIp", raw.srcIp());
        m.put("dstIp", raw.dstIp());
        m.put("host", raw.host());
        m.put("attributes", raw.attributes());
        return m;
    }

    @Test
    void localEventStreamYieldsStableExplainableResults() {
        TestLogger.section("EndToEndPipelineTest.localEventStreamYieldsStableExplainableResults");
        // 基线已在 @BeforeEach 灌入：直接核对确定性结论
        TestLogger.state("唯一接受计数", ingestionService.acceptedCount());
        TestLogger.state("告警总数", alertService.size());

        assertEquals(9, ingestionService.acceptedCount(), "唯一接受事件数");
        assertEquals(2, alertService.size());

        int bruteAlerts = 0;
        int c2Alerts = 0;
        for (Alert a : alertService.list()) {
            if (a.ruleId().equals("R-BRUTE-FORCE")) {
                bruteAlerts++;
                assertEquals(3, a.eventCount(), "暴力破解会话恰好纳入 3 个贡献事件");
            }
            if (a.ruleId().equals("R-C2-BEACON")) {
                c2Alerts++;
                assertEquals("KNOWN_BAD_IP:malware-c2", a.enrichment().get("threatIntel.srcIp"));
            }
        }
        TestLogger.state("暴力破解/C2 告警数", bruteAlerts + "/" + c2Alerts);
        assertEquals(1, bruteAlerts, "乱序补全 + 重复抑制后只产生 1 个暴力破解告警");
        assertEquals(1, c2Alerts);

        List<Alert> alerts = alertService.list();
        TestLogger.state("最终告警", alerts.stream().map(a -> a.alertId() + ":" + a.state()
                + ":events=" + a.eventCount() + ":enriched=" + a.enrichment()).toList());
        alerts.forEach(a -> assertTrue(a.enrichment().containsKey("ruleId")));
    }

    @Test
    void httpLayerExposesEventsAlertsRulesAndRejectsInvalidAction() throws Exception {
        TestLogger.section("EndToEndPipelineTest.httpLayerExposesEventsAlertsRulesAndRejectsInvalidAction");
        // 规则列表
        mockMvc.perform(get("/api/rules"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.ruleId=='R-BRUTE-FORCE' && @.version=='v2')]").exists());

        // 重复提交基线中的 a-1 -> 接受但标记 duplicate（不重复计数/告警）
        RawEvent dup = DemoScenario.events().get(0);
        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(dup))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.duplicate").value(true));

        // 一条全新的合法事件 -> 接受且非重复
        RawEvent fresh = new RawEvent("WEB_GATEWAY", "ACCESS_DENIED",
                com.github.lisama569.siemalertcorrelationjava.stream.LocalEventStream.iso(
                        com.github.lisama569.siemalertcorrelationjava.stream.LocalEventStream.baseTime()),
                "fresh-e2e-1", "zoe", "10.0.0.50", "10.0.0.1", null, Map.of());
        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(fresh))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.duplicate").value(false));

        // 提交一个缺来源的非法事件 -> 422 + 错误码
        RawEvent bad = DemoScenario.events().stream()
                .filter(r -> "bad-1".equals(r.rawId())).findFirst().orElseThrow();
        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(bad))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("E101"));

        // 告警列表可查
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk());

        // 未知告警处置 -> 404
        mockMvc.perform(post("/api/alerts/ALERT-ghost/actions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"action\":\"CLOSE\",\"actor\":\"t\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("A205"));

        // 非法动作 -> 400 A206
        Alert any = alertService.list().stream().findFirst().orElseThrow();
        mockMvc.perform(post("/api/alerts/" + any.alertId() + "/actions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"action\":\"EXPLODE\",\"actor\":\"t\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("A206"));
        TestLogger.result("HTTP 用例", "规则查询/事件接受/事件拒绝/未知告警/非法动作 全部断言通过");
    }

    @Test
    void alertLifecycleThroughHttpIsTraceable() throws Exception {
        TestLogger.section("EndToEndPipelineTest.alertLifecycleThroughHttpIsTraceable");
        Alert target = alertService.list().stream()
                .filter(a -> a.ruleId().equals("R-BRUTE-FORCE"))
                .findFirst().orElseThrow();
        long version = target.version();

        // 用过期版本号关闭 -> 409 冲突
        mockMvc.perform(post("/api/alerts/" + target.alertId() + "/actions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"action\":\"CLOSE\",\"actor\":\"t\",\"expectedVersion\":" + (version - 1) + "}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("A204"));

        // 正常关闭
        mockMvc.perform(post("/api/alerts/" + target.alertId() + "/actions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"action\":\"CLOSE\",\"actor\":\"analyst-http\",\"reason\":\"已处置\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value(AlertState.CLOSED.name()))
                .andExpect(jsonPath("$.version").value(version + 1));

        // 关闭后再确认 -> 422 A203
        mockMvc.perform(post("/api/alerts/" + target.alertId() + "/actions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"action\":\"ACKNOWLEDGE\",\"actor\":\"t\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("A203"));

        // 审计链可追溯
        Alert closed = alertService.get(target.alertId()).orElseThrow();
        TestLogger.state("审计链长度", closed.auditTrail().size());
        assertTrue(closed.auditTrail().size() >= 3);
        TestLogger.result("HTTP 生命周期", "版本冲突/关闭/关闭后非法动作 全部可解释、可追溯");
    }
}
