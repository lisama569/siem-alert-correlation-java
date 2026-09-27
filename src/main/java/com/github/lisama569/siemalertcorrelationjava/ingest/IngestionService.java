package com.github.lisama569.siemalertcorrelationjava.ingest;

import com.github.lisama569.siemalertcorrelationjava.ingest.support.NetworkAddresses;
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
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 事件接入服务：归一化 + 校验 + 幂等去重。
 *
 * <p>字段缺失或语义非法的记录不会被静默丢弃，而是返回
 * {@link IngestResult.Rejected} 并携带可区分的 {@link RejectReason}；
 * 同一 eventId 重复提交返回 {@link IngestResult.Duplicate}，
 * 不会进入后续检测，因此不会产生重复计数或重复告警。
 *
 * <p>校验顺序固定（与字段在记录中的排列无关），同一条记录每次提交拿到的拒绝原因
 * 一定相同：
 * <ol>
 *   <li>{@code MISSING_EVENT_ID} → {@code MISSING_SOURCE} → {@code UNKNOWN_SOURCE}</li>
 *   <li>{@code MISSING_TYPE} → {@code UNKNOWN_EVENT_TYPE}</li>
 *   <li>{@code MISSING_OCCURRED_AT} → {@code INVALID_TIMESTAMP} →
 *       {@code FUTURE_TIMESTAMP}</li>
 *   <li>{@code INVALID_IP_ADDRESS}（属性中表示网络地址的字段，字段名按字典序逐个检查，
 *       只报第一个非法字段，保证结果稳定）</li>
 *   <li>以上全部通过后才进行幂等去重，因此被拒绝的记录永远不会占用 eventId 名额。</li>
 * </ol>
 */
public class IngestionService {

    /** 受认可的默认来源集合：只接受这些来源提交的事件。 */
    public static final Set<String> DEFAULT_ALLOWED_SOURCES =
            Set.of("auth-gateway", "firewall", "ids", "edr", "proxy");

    private final Set<String> seenEventIds = ConcurrentHashMap.newKeySet();
    private final Set<String> allowedSources;
    private final Clock clock;

    public IngestionService() {
        this(Clock.systemUTC(), DEFAULT_ALLOWED_SOURCES);
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
        String eventId = raw.eventId().trim();
        if (isBlank(raw.source())) {
            return new IngestResult.Rejected(RejectReason.MISSING_SOURCE,
                    "source 为空, eventId=" + eventId);
        }
        String source = raw.source().trim();
        if (!allowedSources.contains(source)) {
            return new IngestResult.Rejected(RejectReason.UNKNOWN_SOURCE,
                    "来源不在受认可的来源集合中: " + source + ", eventId=" + eventId
                            + ", 允许的来源=" + allowedSources);
        }
        if (isBlank(raw.type())) {
            return new IngestResult.Rejected(RejectReason.MISSING_TYPE,
                    "type 为空, eventId=" + eventId);
        }
        EventType type;
        try {
            type = EventType.valueOf(raw.type().trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return new IngestResult.Rejected(RejectReason.UNKNOWN_EVENT_TYPE,
                    "未知事件类型: " + raw.type() + ", eventId=" + eventId);
        }
        if (isBlank(raw.occurredAt())) {
            return new IngestResult.Rejected(RejectReason.MISSING_OCCURRED_AT,
                    "occurredAt 为空, eventId=" + eventId);
        }
        Instant occurredAt;
        try {
            occurredAt = Instant.parse(raw.occurredAt().trim());
        } catch (DateTimeParseException e) {
            return new IngestResult.Rejected(RejectReason.INVALID_TIMESTAMP,
                    "occurredAt 不是合法 ISO-8601: " + raw.occurredAt()
                            + ", eventId=" + eventId);
        }
        if (occurredAt.isAfter(Instant.now(clock))) {
            return new IngestResult.Rejected(RejectReason.FUTURE_TIMESTAMP,
                    "occurredAt 晚于当前时间(来自未来): " + occurredAt + ", eventId=" + eventId);
        }
        // 网络地址字段：字段名按字典序固定顺序检查，只返回第一个非法字段，保证拒绝原因稳定
        TreeMap<String, String> sortedAttrs = new TreeMap<>(
                raw.attributes() == null ? Map.of() : raw.attributes());
        for (Map.Entry<String, String> attr : sortedAttrs.entrySet()) {
            String key = attr.getKey();
            if (NetworkAddresses.isAddressField(key)
                    && !NetworkAddresses.isValidLiteral(attr.getValue())) {
                return new IngestResult.Rejected(RejectReason.INVALID_IP_ADDRESS,
                        "网络地址字段 " + key + " 的值不是合法 IPv4/IPv6 字面量: "
                                + attr.getValue() + ", eventId=" + eventId);
            }
        }

        // 2. 幂等去重：先占位再返回，保证并发重复提交只放行一次
        if (!seenEventIds.add(eventId)) {
            return new IngestResult.Duplicate(eventId);
        }

        SecurityEvent event = new SecurityEvent(
                eventId, source, type, occurredAt,
                Instant.now(clock), raw.attributes());
        return new IngestResult.Accepted(event);
    }

    /** 已接受（去重后）的事件数量，用于核对重复提交未产生重复计数。 */
    public int acceptedCount() {
        return seenEventIds.size();
    }

    /** 当前受认可的来源集合（不可变快照）。 */
    public Set<String> allowedSources() {
        return allowedSources;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
