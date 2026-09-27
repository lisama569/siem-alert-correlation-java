package com.github.lisama569.siemalertcorrelationjava.ingest;

import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.RejectReason;
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 事件接入服务：归一化 + 校验 + 幂等去重。
 *
 * <p>校验顺序固定（同一条记录每次得到的拒绝原因都相同）：
 * <ol>
 *   <li>eventId 为空 → {@link RejectReason#MISSING_EVENT_ID}</li>
 *   <li>source 为空 → {@link RejectReason#MISSING_SOURCE}</li>
 *   <li>source 不在认可来源集合 → {@link RejectReason#UNKNOWN_SOURCE}</li>
 *   <li>type 为空 → {@link RejectReason#MISSING_TYPE}</li>
 *   <li>type 不在枚举内 → {@link RejectReason#UNKNOWN_EVENT_TYPE}</li>
 *   <li>occurredAt 为空 → {@link RejectReason#MISSING_OCCURRED_AT}</li>
 *   <li>occurredAt 非 ISO-8601 → {@link RejectReason#INVALID_TIMESTAMP}</li>
 *   <li>occurredAt 晚于当前接收时间（未来事件）→ {@link RejectReason#FUTURE_TIMESTAMP}</li>
 *   <li>网络地址字段（{@link #IP_ATTRIBUTE_KEYS}）值非法 → {@link RejectReason#INVALID_FIELD_VALUE}</li>
 * </ol>
 *
 * <p>全部被拒记录都不会进入去重集合，也不会被静默丢弃；
 * 同一 eventId 重复提交返回 {@link IngestResult.Duplicate}，
 * 不进入后续检测，不会重复计数或重复告警。
 */
public class IngestionService {

    /** 默认认可的来源集合（可用构造参数覆盖）。 */
    public static final Set<String> DEFAULT_ALLOWED_SOURCES = Set.of(
            "auth-gateway", "firewall", "ids", "edr", "dns-proxy");

    /** 属性中按网络地址校验的字段名。 */
    public static final Set<String> IP_ATTRIBUTE_KEYS = Set.of(
            "ip", "srcIp", "dstIp", "sourceIp", "destinationIp");

    private final Set<String> seenEventIds = ConcurrentHashMap.newKeySet();
    private final Clock clock;
    private final Set<String> allowedSources;

    public IngestionService() {
        this(Clock.systemUTC());
    }

    public IngestionService(Clock clock) {
        this(clock, DEFAULT_ALLOWED_SOURCES);
    }

    public IngestionService(Clock clock, Set<String> allowedSources) {
        this.clock = clock;
        this.allowedSources = Set.copyOf(allowedSources);
    }

    public IngestResult ingest(RawEvent raw) {
        // 1. 校验与归一化（顺序固定，任何一步失败都返回可区分原因）
        if (isBlank(raw.eventId())) {
            return new IngestResult.Rejected(RejectReason.MISSING_EVENT_ID, "eventId 为空");
        }
        if (isBlank(raw.source())) {
            return new IngestResult.Rejected(RejectReason.MISSING_SOURCE,
                    "source 为空, eventId=" + raw.eventId());
        }
        String source = raw.source().trim();
        if (!allowedSources.contains(source)) {
            return new IngestResult.Rejected(RejectReason.UNKNOWN_SOURCE,
                    "来源不在认可集合: " + source + ", eventId=" + raw.eventId());
        }
        if (isBlank(raw.type())) {
            return new IngestResult.Rejected(RejectReason.MISSING_TYPE,
                    "type 为空, eventId=" + raw.eventId());
        }
        EventType type;
        try {
            type = EventType.valueOf(raw.type().trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return new IngestResult.Rejected(RejectReason.UNKNOWN_EVENT_TYPE,
                    "未知事件类型: " + raw.type() + ", eventId=" + raw.eventId());
        }
        if (isBlank(raw.occurredAt())) {
            return new IngestResult.Rejected(RejectReason.MISSING_OCCURRED_AT,
                    "occurredAt 为空, eventId=" + raw.eventId());
        }
        Instant occurredAt;
        try {
            occurredAt = Instant.parse(raw.occurredAt().trim());
        } catch (DateTimeParseException e) {
            return new IngestResult.Rejected(RejectReason.INVALID_TIMESTAMP,
                    "occurredAt 不是合法 ISO-8601: " + raw.occurredAt()
                            + ", eventId=" + raw.eventId());
        }
        if (occurredAt.isAfter(Instant.now(clock))) {
            return new IngestResult.Rejected(RejectReason.FUTURE_TIMESTAMP,
                    "occurredAt 晚于当前接收时间（未来事件）: " + occurredAt
                            + ", eventId=" + raw.eventId());
        }
        for (Map.Entry<String, String> attr : raw.attributes().entrySet()) {
            if (IP_ATTRIBUTE_KEYS.contains(attr.getKey())
                    && !IpValidator.isValid(attr.getValue())) {
                return new IngestResult.Rejected(RejectReason.INVALID_FIELD_VALUE,
                        "字段 " + attr.getKey() + " 不是合法网络地址: " + attr.getValue()
                                + ", eventId=" + raw.eventId());
            }
        }

        // 2. 幂等去重：先占位再返回，保证并发重复提交只放行一次
        if (!seenEventIds.add(raw.eventId())) {
            return new IngestResult.Duplicate(raw.eventId());
        }

        SecurityEvent event = new SecurityEvent(
                raw.eventId(), source, type, occurredAt,
                Instant.now(clock), raw.attributes());
        return new IngestResult.Accepted(event);
    }

    /** 已接受（去重后）的事件数量，用于核对重复提交未产生重复计数。 */
    public int acceptedCount() {
        return seenEventIds.size();
    }

    /** 当前生效的认可来源集合（只读视图）。 */
    public Set<String> allowedSources() {
        return allowedSources;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
