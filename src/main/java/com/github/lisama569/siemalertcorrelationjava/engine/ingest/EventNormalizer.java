package com.github.lisama569.siemalertcorrelationjava.engine.ingest;

import com.github.lisama569.siemalertcorrelationjava.common.util.IpValidator;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventSource;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.event.IngestionOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.event.RejectionReason;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 多来源事件归一化器：原始弱类型事件 → 强类型 SecurityEvent。
 * 字段缺失/语义非法时返回带 {@link RejectionReason} 的拒绝结果，绝不静默丢弃。
 * 拒绝判定顺序固定（source → type → time → IP），保证原因可复现、可区分。
 */
@Component
public class EventNormalizer {

    private static final Logger log = LoggerFactory.getLogger(EventNormalizer.class);

    /** 未来时间容忍：超过当前时间 60s 的事件时间判为非法（时钟漂移保护）。 */
    public static final long FUTURE_TOLERANCE_MS = 60_000L;

    /**
     * 归一化单条原始事件。
     *
     * @param raw   原始事件
     * @param nowMs 当前时间（注入时钟，保证测试确定）
     */
    public IngestionOutcome normalize(RawEvent raw, long nowMs) {
        if (raw == null) {
            return reject(null, RejectionReason.MISSING_SOURCE, "事件体为空");
        }
        // 1) 来源
        String sourceText = trim(raw.source());
        if (sourceText == null) {
            return reject(raw.rawId(), RejectionReason.MISSING_SOURCE, "source 字段缺失");
        }
        EventSource source = parseEnum(EventSource.class, sourceText);
        if (source == null) {
            return reject(raw.rawId(), RejectionReason.UNKNOWN_SOURCE, "无法识别的来源: " + sourceText);
        }
        // 2) 类型
        String typeText = trim(raw.type());
        if (typeText == null) {
            return reject(raw.rawId(), RejectionReason.MISSING_TYPE, "type 字段缺失");
        }
        EventType type = parseEnum(EventType.class, typeText);
        if (type == null) {
            return reject(raw.rawId(), RejectionReason.UNKNOWN_TYPE, "无法识别的类型: " + typeText);
        }
        // 3) 时间
        String timeText = trim(raw.eventTime());
        if (timeText == null) {
            return reject(raw.rawId(), RejectionReason.MISSING_EVENT_TIME, "eventTime 字段缺失");
        }
        Long eventTime = parseEpochMillis(timeText);
        if (eventTime == null) {
            return reject(raw.rawId(), RejectionReason.INVALID_EVENT_TIME, "eventTime 不是合法 ISO-8601: " + timeText);
        }
        if (eventTime > nowMs + FUTURE_TOLERANCE_MS) {
            return reject(raw.rawId(), RejectionReason.EVENT_TIME_IN_FUTURE,
                    "eventTime=" + eventTime + " 超过当前时间 " + nowMs + " 的未来容忍 " + FUTURE_TOLERANCE_MS + "ms");
        }
        // 4) IP 语义（缺失合法，出现即必须合法）
        if (!IpValidator.isValid(raw.srcIp())) {
            return reject(raw.rawId(), RejectionReason.INVALID_SOURCE_IP, "srcIp 语义非法: " + raw.srcIp());
        }
        if (!IpValidator.isValid(raw.dstIp())) {
            return reject(raw.rawId(), RejectionReason.INVALID_DEST_IP, "dstIp 语义非法: " + raw.dstIp());
        }

        String eventId = buildEventId(source, raw.rawId(), raw, eventTime);
        SecurityEvent event = new SecurityEvent(
                eventId, source, type, eventTime, nowMs,
                trim(raw.user()), trim(raw.srcIp()), trim(raw.dstIp()), trim(raw.host()),
                raw.attributes());
        log.debug("归一化接受 rawId={} -> eventId={} type={} eventTime={}",
                raw.rawId(), eventId, type, eventTime);
        return new IngestionOutcome(true, false, eventId, event, null, null);
    }

    /**
     * 确定性事件 ID：
     * 有 rawId 时 = 来源 + "#" + rawId（跨来源不撞 ID，同源同 ID 即同一事件）；
     * 无 rawId 时 = 来源 + "#" + 内容指纹（SHA-256 前 16 位十六进制）。
     */
    static String buildEventId(EventSource source, String rawId, RawEvent raw, long eventTime) {
        String rid = trim(rawId);
        if (rid != null) {
            return source.name() + "#" + rid;
        }
        String material = String.join("|",
                source.name(),
                String.valueOf(eventTime),
                nz(raw.type()), nz(raw.user()), nz(raw.srcIp()), nz(raw.dstIp()), nz(raw.host()),
                raw.attributes() == null ? "" : raw.attributes().toString());
        return source.name() + "#" + sha256Short(material);
    }

    private static String sha256Short(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", digest[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private static Long parseEpochMillis(String text) {
        try {
            return OffsetDateTime.parse(text).toInstant().toEpochMilli();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static <E extends Enum<E>> E parseEnum(Class<E> enumType, String text) {
        String normalized = text.trim().toUpperCase().replaceAll("[^A-Z0-9]+", "_")
                .replaceAll("^_+|_+$", "");
        try {
            return Enum.valueOf(enumType, normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String trim(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }

    private static IngestionOutcome reject(String rawId, RejectionReason reason, String detail) {
        log.debug("归一化拒绝 rawId={} code={} reason={} detail={}",
                rawId, reason.code(), reason.name(), detail);
        return new IngestionOutcome(false, false, null, null, reason, detail);
    }
}
