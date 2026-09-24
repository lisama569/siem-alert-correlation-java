package com.github.lisama569.siemalertcorrelationjava.detection;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import java.util.List;

/** 一批事件检测后的产出：新告警与可解释的判定说明。 */
public record DetectionResult(List<Alert> newAlerts, List<String> notes) {
}
