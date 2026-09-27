package com.github.lisama569.siemalertcorrelationjava.api;

import java.util.List;

/**
 * 单条事件接入的 HTTP 响应。
 *
 * @param result        ACCEPTED / DUPLICATE / REJECTED
 * @param eventId       事件 ID（可能为 null，如缺失时）
 * @param reason        拒绝原因（仅 REJECTED 时非空，取值见 RejectReason）
 * @param detail        可读的判定说明
 * @param alertsCreated 本次受理后新触发的告警 ID 列表
 */
public record IngestResponse(
        String result,
        String eventId,
        String reason,
        String detail,
        List<String> alertsCreated) {

    public static IngestResponse accepted(String eventId, List<String> alertsCreated) {
        return new IngestResponse("ACCEPTED", eventId, null, null, alertsCreated);
    }

    public static IngestResponse duplicate(String eventId) {
        return new IngestResponse("DUPLICATE", eventId, null,
                "该 eventId 已被接受过，未重复计数", List.of());
    }

    public static IngestResponse rejected(String eventId, String reason, String detail) {
        return new IngestResponse("REJECTED", eventId, reason, detail, List.of());
    }
}
