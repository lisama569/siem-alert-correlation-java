package com.github.lisama569.siemalertcorrelationjava.demo;

import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.stream.LocalEventStream;
import java.util.List;

/**
 * 端到端演示期望（与 {@link LocalEventStream} 的数据集一一对应），
 * 供 DemoRunner 在运行末尾逐条核对并打印"输入 → 判定依据 → 最终状态"。
 */
public final class DemoScenario {

    private DemoScenario() {
    }

    public static List<RawEvent> events() {
        return LocalEventStream.scenario();
    }

    public static List<Expectation> expectations() {
        return List.of(
                new Expectation("D1", "alice 的 4 次 LOGIN_FAILED（含容忍范围内乱序 a-3）只产生 1 个暴力破解告警，阈值=3"),
                new Expectation("D2", "重复提交的 a-2 被标记 duplicate，accepted 计数不增加、不产生新告警"),
                new Expectation("D3", "198.51.100.23 的 2 次 MALWARE_DETECTED 产生 1 个 C2 告警并富化本地情报"),
                new Expectation("D4", "09:30 的历史事件超出容忍迟到范围，结论 REJECTED_TOO_LATE"),
                new Expectation("D5", "5 条非法记录分别被 E101/E104/E106/E108/E107 拒绝，原因互不相同且不静默丢弃"),
                new Expectation("D6", "erin 仅 2 次失败，未达阈值，不产生告警"),
                new Expectation("D7", "对 alice 告警并发执行 ACKNOWLEDGE/SUPPRESS/CLOSE 后最终状态确定为 CLOSED，审计链完整"),
                new Expectation("D8", "以规则 R-BRUTE-FORCE:v1(阈值5) 重放同一序列不触发；以 v2(阈值3) 重放触发且指纹与实时一致"));
    }

    public record Expectation(String code, String description) {
    }
}
