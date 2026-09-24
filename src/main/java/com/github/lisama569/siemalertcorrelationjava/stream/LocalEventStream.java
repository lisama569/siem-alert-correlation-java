package com.github.lisama569.siemalertcorrelationjava.stream;

import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

/**
 * 本地事件流：模拟多来源安全日志（确定性数据集，无任何外部依赖）。
 * 时间戳相对于运行时刻动态生成（基准 = 当前 UTC 截断到分钟后再回退 10 分钟），
 * 因此任何时候运行，"过去/乱序/迟到/未来"的语义都稳定一致。
 * 数据集刻意包含：
 * <ul>
 *   <li>正常按序事件；</li>
 *   <li>乱序到达（较早事件晚到，但在容忍范围内）；</li>
 *   <li>超出容忍范围的过迟历史事件；</li>
 *   <li>重复提交（同 rawId 再来一次）；</li>
 *   <li>各类字段缺失/语义非法记录（来源缺失、类型未知、时间非法、IP 非法、未来时间）。</li>
 * </ul>
 */
public final class LocalEventStream {

    private static final long SECOND = 1000L;
    private static final long MINUTE = 60 * SECOND;

    private LocalEventStream() {
    }

    /** 基准时间（epoch 毫秒）：当前时间截断到分钟后回退 10 分钟。 */
    public static long baseTime() {
        return Instant.now().truncatedTo(ChronoUnit.MINUTES).toEpochMilli() - 10 * MINUTE;
    }

    public static String iso(long epochMs) {
        return Instant.ofEpochMilli(epochMs).toString();
    }

    public static List<RawEvent> scenario() {
        long t = baseTime();
        return List.of(
                // --- 暴力破解会话（user=alice）：3 次失败即应触发 R-BRUTE-FORCE:v2 ---
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 0 * MINUTE), "a-1",
                        "alice", "10.0.0.11", "10.0.0.1", null, Map.of()),
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 5 * SECOND), "a-2",
                        "alice", "10.0.0.11", "10.0.0.1", null, Map.of()),
                // 乱序：a-3 事件时间 t+1s 却在 a-2 之后到达，仍在 lateness=5s 容忍内
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 1 * SECOND), "a-3",
                        "alice", "10.0.0.11", "10.0.0.1", null, Map.of()),
                // 同会话第 4 次失败：必须被去重抑制，不能再产生新告警
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 9 * SECOND), "a-4",
                        "alice", "10.0.0.11", "10.0.0.1", null, Map.of()),
                // 重复提交 a-2（同 rawId）：不得重复计数或告警
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 5 * SECOND), "a-2",
                        "alice", "10.0.0.11", "10.0.0.1", null, Map.of()),

                // --- 恶意软件/C2（src=198.51.100.23，命中本地情报），2 次触发 v1 阈值2 ---
                raw("HOST_EDR", "MALWARE_DETECTED", iso(t + 2 * MINUTE), "m-1",
                        "bob", "198.51.100.23", "10.0.0.5", "host-7",
                        Map.of("family", "Emotet")),
                raw("HOST_EDR", "MALWARE_DETECTED", iso(t + 2 * MINUTE + 40 * SECOND), "m-2",
                        "bob", "198.51.100.23", "10.0.0.5", "host-7",
                        Map.of("family", "Emotet")),

                // --- 过迟历史事件：远在水位线之前，必须 REJECTED_TOO_LATE ---
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t - 30 * MINUTE), "late-1",
                        "carol", "10.0.0.77", "10.0.0.1", null, Map.of()),

                // --- 非法/缺失记录：必须被拒绝且原因可区分 ---
                raw(null, "LOGIN_FAILED", iso(t + 3 * MINUTE), "bad-1",
                        "dave", "10.0.0.8", "10.0.0.1", null, Map.of()),                    // 缺来源 E101
                raw("AUTH_SERVICE", "WAT_BUTTERFLY", iso(t + 3 * MINUTE), "bad-2",
                        "dave", "10.0.0.8", "10.0.0.1", null, Map.of()),                    // 未知类型 E104
                raw("AUTH_SERVICE", "LOGIN_FAILED", "not-a-time", "bad-3",
                        "dave", "10.0.0.8", "10.0.0.1", null, Map.of()),                    // 时间非法 E106
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 3 * MINUTE), "bad-4",
                        "dave", "999.1.1.1", "10.0.0.1", null, Map.of()),                   // IP 非法 E108
                raw("AUTH_SERVICE", "LOGIN_FAILED", Instant.now().plus(365, ChronoUnit.DAYS)
                        .truncatedTo(ChronoUnit.SECONDS).toString(), "bad-5",
                        "dave", "10.0.0.8", "10.0.0.1", null, Map.of()),                    // 未来时间 E107

                // --- 独立用户 erin 仅 2 次失败，不足阈值 3，不应触发 ---
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 4 * MINUTE), "e-1",
                        "erin", "10.0.0.12", "10.0.0.1", null, Map.of()),
                raw("AUTH_SERVICE", "LOGIN_FAILED", iso(t + 4 * MINUTE + 10 * SECOND), "e-2",
                        "erin", "10.0.0.12", "10.0.0.1", null, Map.of())
        );
    }

    private static RawEvent raw(String source, String type, String time, String rawId,
                                String user, String srcIp, String dstIp, String host,
                                Map<String, String> attributes) {
        return new RawEvent(source, type, time, rawId, user, srcIp, dstIp, host, attributes);
    }
}
