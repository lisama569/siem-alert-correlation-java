package com.github.lisama569.siemalertcorrelationjava.tests;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * HTTP 入口测试：验证 受理/重复/拒绝/查不到/状态冲突 五类结果可区分，
 * 且被拒绝时能看出具体原因。
 *
 * <p>注意：Spring 上下文在用例间共享（去重集合有状态），
 * 各用例使用互不相同的 eventId / 分组值，避免相互干扰。
 */
@SpringBootTest
@AutoConfigureMockMvc
class ApiControllerTest {

    private static final Logger log = LoggerFactory.getLogger(ApiControllerTest.class);

    @Autowired
    private MockMvc mvc;

    private static String eventJson(String id, String source, String type,
                                    String occurredAt, String attributes) {
        return """
                {"eventId":"%s","source":"%s","type":"%s","occurredAt":"%s","attributes":%s}
                """.formatted(id, source, type, occurredAt, attributes);
    }

    @Test
    void ingestDistinguishesAcceptedDuplicateRejected() throws Exception {
        String json = eventJson("api-e1", "firewall", "LOGIN_FAILED",
                "2026-09-24T08:00:00Z", "{\"user\":\"api-user-0\"}");

        // 1. 正常受理 -> 201 ACCEPTED
        MvcResult first = mvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.result").value("ACCEPTED"))
                .andExpect(jsonPath("$.eventId").value("api-e1"))
                .andReturn();
        log.info("首次提交: {}", first.getResponse().getContentAsString());

        // 2. 重复提交 -> 200 DUPLICATE（与受理可区分，且不重复计数）
        mvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("DUPLICATE"));

        // 3. 各类拒绝 -> 422，且 reason 可区分
        assertRejected(eventJson("api-e2", "strange-box", "LOGIN_FAILED",
                "2026-09-24T08:00:00Z", "{}"), "UNKNOWN_SOURCE");
        assertRejected(eventJson("api-e3", "firewall", "LOGIN_FAILED",
                "2999-01-01T00:00:00Z", "{}"), "FUTURE_TIMESTAMP");
        assertRejected(eventJson("api-e4", "firewall", "NETWORK_CONNECTION",
                "2026-09-24T08:00:00Z", "{\"srcIp\":\"999.1.1.1\"}"), "INVALID_FIELD_VALUE");
        assertRejected(eventJson("api-e5", "firewall", "NOPE",
                "2026-09-24T08:00:00Z", "{}"), "UNKNOWN_EVENT_TYPE");
    }

    private void assertRejected(String json, String reason) throws Exception {
        MvcResult r = mvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.result").value("REJECTED"))
                .andExpect(jsonPath("$.reason").value(reason))
                .andExpect(jsonPath("$.detail", not(emptyOrNullString())))
                .andReturn();
        log.info("拒绝[{}]: {}", reason, r.getResponse().getContentAsString());
    }

    @Test
    void alertQueryAndTransitionsOverHttp() throws Exception {
        // 提交 3 条同账号登录失败，触发 brute-force-login 告警
        String alertId = null;
        for (int i = 0; i < 3; i++) {
            MvcResult r = mvc.perform(post("/api/events")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(eventJson("api-trig-" + i, "auth-gateway", "LOGIN_FAILED",
                                    "2026-09-24T08:00:0" + i + "Z",
                                    "{\"user\":\"api-user-1\"}")))
                    .andExpect(status().isCreated())
                    .andReturn();
            String body = r.getResponse().getContentAsString();
            log.info("触发提交 {}: {}", i, body);
            if (i == 2) {
                assertTrue(body.contains("brute-force-login-v1-api-user-1-"),
                        "第 3 次失败应触发告警: " + body);
                alertId = com.jayway.jsonpath.JsonPath.read(body, "$.alertsCreated[0]");
            }
        }
        log.info("告警编号: {}", alertId);

        // 按编号查询 -> 200，含处置历史（此时为空）
        mvc.perform(get("/api/alerts/{id}", alertId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alertId").value(alertId))
                .andExpect(jsonPath("$.status").value("OPEN"))
                .andExpect(jsonPath("$.history", hasSize(0)));

        // 查不到 -> 404
        mvc.perform(get("/api/alerts/{id}", "no-such-alert"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ALERT_NOT_FOUND"));

        // 确认 -> 200 SUCCESS，版本 0 -> 1
        mvc.perform(post("/api/alerts/{id}/acknowledge", alertId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"op-http\",\"note\":\"确认\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("SUCCESS"))
                .andExpect(jsonPath("$.alert.status").value("ACKNOWLEDGED"))
                .andExpect(jsonPath("$.alert.version").value(1));

        // 携带过期版本关闭 -> 409 VERSION_CONFLICT
        mvc.perform(post("/api/alerts/{id}/close", alertId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"op-http\",\"expectedVersion\":0}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("VERSION_CONFLICT"));

        // 正确版本关闭 -> 200
        mvc.perform(post("/api/alerts/{id}/close", alertId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"op-http\",\"note\":\"闭环\",\"expectedVersion\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert.status").value("CLOSED"))
                .andExpect(jsonPath("$.alert.version").value(2));

        // 关闭后再确认 -> 409 ALREADY_TERMINAL（与查不到的 404 可区分）
        mvc.perform(post("/api/alerts/{id}/acknowledge", alertId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"op-http\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("ALREADY_TERMINAL"));

        // 对不存在的告警处置 -> 404
        mvc.perform(post("/api/alerts/{id}/close", "no-such-alert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"op-http\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ALERT_NOT_FOUND"));

        // 处置历史可追溯：确认 + 关闭 两条
        mvc.perform(get("/api/alerts/{id}", alertId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.history", hasSize(2)))
                .andExpect(jsonPath("$.history[0].action").value("ACKNOWLEDGE"))
                .andExpect(jsonPath("$.history[1].action").value("CLOSE"));
    }

    @Test
    void batchIngestReportsPerItemOutcomes() throws Exception {
        String batch = """
                [
                  {"eventId":"api-b1","source":"auth-gateway","type":"LOGIN_FAILED","occurredAt":"2026-09-24T08:00:00Z","attributes":{"user":"api-user-2"}},
                  {"eventId":"api-b1","source":"auth-gateway","type":"LOGIN_FAILED","occurredAt":"2026-09-24T08:00:00Z","attributes":{"user":"api-user-2"}},
                  {"eventId":"api-b2","source":"mystery","type":"LOGIN_FAILED","occurredAt":"2026-09-24T08:00:00Z","attributes":{}},
                  {"eventId":"api-b3","source":"auth-gateway","type":"LOGIN_FAILED","occurredAt":"2026-09-24T08:01:00Z","attributes":{"user":"api-user-2"}},
                  {"eventId":"api-b4","source":"auth-gateway","type":"LOGIN_FAILED","occurredAt":"2026-09-24T08:02:00Z","attributes":{"user":"api-user-2"}}
                ]
                """;
        MvcResult r = mvc.perform(post("/api/events/batch")
                        .contentType(MediaType.APPLICATION_JSON).content(batch))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(5))
                .andExpect(jsonPath("$.accepted").value(3))
                .andExpect(jsonPath("$.duplicates").value(1))
                .andExpect(jsonPath("$.rejected").value(1))
                .andExpect(jsonPath("$.items[0].result").value("ACCEPTED"))
                .andExpect(jsonPath("$.items[1].result").value("DUPLICATE"))
                .andExpect(jsonPath("$.items[2].result").value("REJECTED"))
                .andExpect(jsonPath("$.items[2].reason").value("UNKNOWN_SOURCE"))
                .andExpect(jsonPath("$.alertsCreated", hasSize(1)))
                .andReturn();
        log.info("批量结果: {}", r.getResponse().getContentAsString());
    }
}
