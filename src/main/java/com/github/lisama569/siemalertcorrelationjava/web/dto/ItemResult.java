package com.github.lisama569.siemalertcorrelationjava.web.dto;

/**
 * 单条事件的接入结果视图。
 *
 * @param outcome ACCEPTED / DUPLICATE / REJECTED
 * @param reason  被拒绝时的 {@code RejectReason} 名称，其余情况为 null
 * @param detail  人类可读说明
 * @param eventId 事件 ID（重复/拒绝时按提交值回填，便于对齐批次顺序）
 */
public record ItemResult(String outcome, String eventId, String reason, String detail) {
}
