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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 入口集成测试：正常受理 / 重复提交 / 各类拒绝 / 查不到 / 各类状态冲突
 * 必须返回可区分的状态码与机读原因；链路全部在本地内存完成。
 */
@SpringBootTest
@AutoConfigureMockMvc
class HttpApiTest {

    private static final Logger log = LoggerFactory.getLogger(HttpApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    private static String event(String id, String source, String type, String at,
                                String user, String srcIp) {
        StringBuilder sb = new StringBuilder("{")
                .append("\"eventId\":\"").append(id).append("\"")
                .append(",\"source\":\"").append(source).append("\"")
                .append(",\"type\":\"").append(type).append("\"")
                .append(",\"occurredAt\":\"").append(at).append("\"")
                .append(",\"attributes\":{");
        if (user != null) {
            sb.append("\"user\":\"").append(user).append("\"");
        }
        if (srcIp != null) {
            if (user != null) {
                sb.append(",");
            }
            sb.append("\"srcIp\":\"").append(srcIp).append("\"");
        }
        return sb.append("}}").toString();
    }

    private MvcResult postJson(String url, String body) throws Exception {
        return mockMvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(body))
                .andDo(r -> log.info("POST {} -> {} {}", url,
                        r.getResponse().getStatus(), r.getResponse().getContentAsString()))
                .andReturn();
    }

    @Test
    void acceptedDuplicateAndRejectionsAreDistinguished() throws Exception {
        // 正常受理
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                        .content(event("h-1", "firewall", "LOGIN_FAILED",
                                "2026-09-24T08:00:00Z", "http-user-a", "10.0.0.1")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("ACCEPTED"));

        // 重复提交：409 + DUPLICATE
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                        .content(event("h-1", "firewall", "LOGIN_FAILED",
                                "2026-09-24T08:00:00Z", "http-user-a", "10.0.0.1")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.outcome").value("DUPLICATE"))
                .andExpect(jsonPath("$.reason").doesNotExist());

        // 未知来源：422 + 明确原因
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                        .content(event("h-2", "rogue-syslog", "LOGIN_FAILED",
                                "2026-09-24T08:00:00Z", "u", null)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.outcome").value("REJECTED"))
                .andExpect(jsonPath("$.reason").value("UNKNOWN_SOURCE"));

        // 未来时间戳：422 + FUTURE_TIMESTAMP
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                        .content(event("h-3", "edr", "LOGIN_FAILED",
                                "2099-01-01T00:00:00Z", "u", null)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.reason").value("FUTURE_TIMESTAMP"));

        // 非法网络地址：422 + INVALID_IP_ADDRESS
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                        .content(event("h-4", "edr", "NETWORK_CONNECTION",
                                "2026-09-24T08:00:00Z", "u", "not-an-ip")))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.reason").value("INVALID_IP_ADDRESS"));

        // 非法 JSON：400 + MALFORMED_REQUEST
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                        .content("{ not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST"));
    }

    @Test
    void batchReportsPerItemOutcomes() throws Exception {
        String batch = "{\"events\":["
                // 受理
                + event("h-b1", "firewall", "LOGIN_FAILED",
                "2026-09-24T08:01:00Z", "http-batch-user", "10.0.0.2") + ","
                // 受理（累计 2 条，不触发阈值 3）
                + event("h-b2", "firewall", "LOGIN_FAILED",
                "2026-09-24T08:01:20Z", "http-batch-user", "10.0.0.3") + ","
                // 与本批首条重复：DUPLICATE
                + event("h-b1", "firewall", "LOGIN_FAILED",
                "2026-09-24T08:01:00Z", "http-batch-user", "10.0.0.2") + ","
                // 未认可来源：REJECTED
                + event("h-b3", "unknown-src", "LOGIN_FAILED",
                "2026-09-24T08:01:40Z", "http-batch-user", null)
                + "]}";
        mockMvc.perform(post("/api/events/batch").contentType(MediaType.APPLICATION_JSON)
                        .content(batch))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(4))
                .andExpect(jsonPath("$.accepted").value(2))
                .andExpect(jsonPath("$.duplicate").value(1))
                .andExpect(jsonPath("$.rejected").value(1))
                .andExpect(jsonPath("$.items[0].outcome").value("ACCEPTED"))
                .andExpect(jsonPath("$.items[1].outcome").value("ACCEPTED"))
                .andExpect(jsonPath("$.items[2].outcome").value("DUPLICATE"))
                .andExpect(jsonPath("$.items[3].outcome").value("REJECTED"))
                .andExpect(jsonPath("$.items[3].reason").value("UNKNOWN_SOURCE"));

        // 空批次：400
        mockMvc.perform(post("/api/events/batch").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"events\":[]}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void alertQueryAndTransitionsAreDistinguished() throws Exception {
        String user = "http-flow-user";
        // 使用独立且晚于其它测试的事件时间窗口（仍早于今天，不触发未来时间戳拒绝），
        // 避免共享内存单例上其它测试已推进的规则水位线把这些事件判为 DROP_LATE。
        postJson("/api/events", event("h-f1", "firewall", "LOGIN_FAILED",
                "2026-09-26T09:00:00Z", user, "10.1.0.1"));
        postJson("/api/events", event("h-f2", "firewall", "LOGIN_FAILED",
                "2026-09-26T09:00:20Z", user, "10.1.0.2"));
        postJson("/api/events", event("h-f3", "firewall", "LOGIN_FAILED",
                "2026-09-26T09:00:40Z", user, "10.1.0.3"));

        // 告警 ID 沿用既有确定性编号规则：ruleId-v版本-分组值-窗口起点epochMillis
        String alertId = "brute-force-login-v1-" + user + "-1790413200000";

        // 按编号查询：含富化、关联事件与处置历史
        mockMvc.perform(get("/api/alerts/" + alertId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alertId").value(alertId))
                .andExpect(jsonPath("$.status").value("OPEN"))
                .andExpect(jsonPath("$.version").value(0))
                .andExpect(jsonPath("$.eventIds.length()").value(3))
                .andExpect(jsonPath("$.history.length()").value(0));

        // 查不到：404
        mockMvc.perform(get("/api/alerts/no-such-alert"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ALERT_NOT_FOUND"));

        // 确认：200，状态与版本推进
        mockMvc.perform(post("/api/alerts/" + alertId + "/acknowledge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"ops-1\",\"note\":\"已确认\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("APPLIED"))
                .andExpect(jsonPath("$.alert.status").value("ACKNOWLEDGED"))
                .andExpect(jsonPath("$.alert.version").value(1));

        // ACKNOWLEDGED -> ACKNOWLEDGED：非法跃迁 409
        mockMvc.perform(post("/api/alerts/" + alertId + "/acknowledge")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("ILLEGAL_TRANSITION"));

        // 过期乐观版本：409 VERSION_CONFLICT
        mockMvc.perform(post("/api/alerts/" + alertId + "/close")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"ops-1\",\"expectedVersion\":0}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("VERSION_CONFLICT"));

        // 关闭：200，版本连续到 2
        mockMvc.perform(post("/api/alerts/" + alertId + "/close")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"operator\":\"ops-2\",\"note\":\"闭环\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert.status").value("CLOSED"))
                .andExpect(jsonPath("$.alert.version").value(2));

        // 终态再操作：409 ALREADY_TERMINAL（不被并发/重复改回）
        mockMvc.perform(post("/api/alerts/" + alertId + "/suppress")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("ALREADY_TERMINAL"));

        // 处置不存在的告警：404
        mockMvc.perform(post("/api/alerts/ghost/close")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ALERT_NOT_FOUND"));

        // 非法动作：400
        mockMvc.perform(post("/api/alerts/" + alertId + "/explode")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_ACTION"));

        // 最终快照：终态、版本 2、历史 2 条且链连续
        mockMvc.perform(get("/api/alerts/" + alertId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CLOSED"))
                .andExpect(jsonPath("$.version").value(2))
                .andExpect(jsonPath("$.history.length()").value(2))
                .andExpect(jsonPath("$.history[0].from").value("OPEN"))
                .andExpect(jsonPath("$.history[0].to").value("ACKNOWLEDGED"))
                .andExpect(jsonPath("$.history[1].from").value("ACKNOWLEDGED"))
                .andExpect(jsonPath("$.history[1].to").value("CLOSED"));
    }
}
