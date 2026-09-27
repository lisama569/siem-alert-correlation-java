package com.github.lisama569.siemalertcorrelationjava.web.dto;

import java.util.List;

/**
 * 批量接入结果：HTTP 固定 200，逐条结果携带各自 outcome，
 * 调用方按 {@link ItemResult#outcome()} 与 {@link ItemResult#reason()} 区分情况。
 */
public record BatchResult(int total, int accepted, int duplicate, int rejected,
                          List<ItemResult> items) {
}
