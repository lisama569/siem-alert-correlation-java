package com.github.lisama569.siemalertcorrelationjava.model.alert;

/**
 * 告警处置命令。
 * expectedVersion 为可选的乐观锁版本；为 null 表示不校验。
 */
public record AlertCommand(
        String alertId,
        AlertAction action,
        String actor,
        String reason,
        Long expectedVersion) {
}
