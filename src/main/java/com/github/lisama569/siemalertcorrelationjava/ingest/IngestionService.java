package com.github.lisama569.siemalertcorrelationjava.ingest;

import com.github.lisama569.siemalertcorrelationjava.model.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.model.RejectReason;
import com.github.lisama569.siemalertcorrelationjava.model.SecurityEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 事件接入服务：归一化 + 校验 + 幂等去重。
 *
 * <p>字段缺失或语义非法的记录不会被静默丢弃，而是返回
 * {@link IngestResult.Rejected} 并携带可区分的 {@link RejectReason}；
 * 同一 eventId 重复提交返回 {@link IngestResult.Duplicate}，
 * 不会进入后续检测，因此不会产生重复计数或重复告警。
 */
public class IngestionService {

    private final Set<String> seenEventIds = ConcurrentHashMap.newKeySet();
    private final Clock clock;

    public IngestionService() {
        this(Clock.systemUTC());
    }

    public IngestionService(Clock clock) {
        this.clock = clock;
    }

    public IngestResult ingest(RawEvent raw) {
        // 1. 校验与归一化（任何一步失败都返回可区分原因）
        if (isBlank(raw.eventId())) {
            return new IngestResult.Rejected(RejectReason.MISSING_EVENT_ID, "eventId 为空");
        }
        if (isBlank(raw.source())) {
            return new IngestResult.Rejected(RejectReason.MISSING_SOURCE,
                    "source 为空, eventId=" + raw.eventId());
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

        // 2. 幂等去重：先占位再返回，保证并发重复提交只放行一次
        if (!seenEventIds.add(raw.eventId())) {
            return new IngestResult.Duplicate(raw.eventId());
        }

        SecurityEvent event = new SecurityEvent(
                raw.eventId(), raw.source().trim(), type, occurredAt,
                Instant.now(clock), raw.attributes());
        return new IngestResult.Accepted(event);
    }

    /** 已接受（去重后）的事件数量，用于核对重复提交未产生重复计数。 */
    public int acceptedCount() {
        return seenEventIds.size();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
