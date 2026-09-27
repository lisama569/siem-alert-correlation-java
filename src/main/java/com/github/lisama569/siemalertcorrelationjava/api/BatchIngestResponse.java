package com.github.lisama569.siemalertcorrelationjava.api;

import java.util.List;

/**
 * 批量接入的 HTTP 响应（整体 200，逐条结果在 items 中区分）。
 *
 * @param alertsCreated 本批新触发的告警 ID 列表
 */
public record BatchIngestResponse(
        int total,
        int accepted,
        int duplicates,
        int rejected,
        List<IngestResponse> items,
        List<String> alertsCreated) {
}
