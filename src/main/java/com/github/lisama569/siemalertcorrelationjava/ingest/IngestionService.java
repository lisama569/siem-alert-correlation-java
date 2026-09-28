package com.github.lisama569.siemalertcorrelationjava.ingest;

import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.RejectReason;
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
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
 *   <li>网络地址字段（命名风格无关，见 {@link IpFieldMatcher}）值非法
 *       → {@link RejectReason#INVALID_IP_ADDRESS}；同一记录有多个地址字段非法时，
 *       按字段名升序在提示中逐一点名，保证每次结果完全一致</li>
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

    /**
     * 网络地址字段按其语义识别，与命名风格无关（见 {@link IpFieldMatcher}）：
     * {@code srcIp}、{@code src_ip}、{@code SRC-IP}、{@code source.ip}、
     * {@code clientIpAddress} 等写法都会被当作地址字段校验。
     */

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
        // 网络地址校验：字段识别与命名风格无关；字段按名升序检查，所有非法字段
        // 一次性收集到固定顺序的提示里，避免 HashMap 遍历顺序导致点名字段漂移。
        List<String> invalidIpFields = new ArrayList<>();
        for (String key : new TreeSet<>(raw.attributes().keySet())) {
            if (IpFieldMatcher.isIpAddressField(key)
                    && !IpValidator.isValid(raw.attributes().get(key))) {
                invalidIpFields.add(key + "=" + raw.attributes().get(key));
            }
        }
        if (!invalidIpFields.isEmpty()) {
            return new IngestResult.Rejected(RejectReason.INVALID_IP_ADDRESS,
                    "网络地址字段不是合法 IPv4/IPv6: " + String.join(", ", invalidIpFields)
                            + ", eventId=" + raw.eventId());
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
