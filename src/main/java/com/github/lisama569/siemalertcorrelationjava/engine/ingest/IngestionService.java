package com.github.lisama569.siemalertcorrelationjava.engine.ingest;

import com.github.lisama569.siemalertcorrelationjava.model.event.IngestionOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.event.RejectionReason;
import java.time.Clock;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 接入服务：归一化 + 确定性去重。
 * 同一 eventId 重复提交只接受一次：第一次 accepted=true，后续 duplicate=true 且不再进入检测，
 * 因此不会产生重复计数或重复告警。拒绝的事件不进入去重集合，可在修正后重新提交。
 */
@Service
public class IngestionService {

    private static final Logger log = LoggerFactory.getLogger(IngestionService.class);

    private final EventNormalizer normalizer;
    private final Clock clock;
    private final Set<String> acceptedEventIds = ConcurrentHashMap.newKeySet();

    public IngestionService(EventNormalizer normalizer, Clock clock) {
        this.normalizer = normalizer;
        this.clock = clock;
    }

    public IngestionOutcome ingest(RawEvent raw) {
        long now = clock.millis();
        IngestionOutcome outcome = normalizer.normalize(raw, now);
        if (!outcome.accepted()) {
            // 拒绝事件原样返回（带原因），不参与去重
            return outcome;
        }
        // addIfAbsent 语义：只有一个线程能插入成功
        boolean firstTime = acceptedEventIds.add(outcome.eventId());
        if (firstTime) {
            log.debug("事件首次接入 eventId={}", outcome.eventId());
            return outcome;
        }
        log.debug("事件重复提交 eventId={}，标记 duplicate，不再计数", outcome.eventId());
        return new IngestionOutcome(true, true, outcome.eventId(), outcome.event(), null,
                "重复事件: " + outcome.eventId());
    }

    public int acceptedCount() {
        return acceptedEventIds.size();
    }

    /** 测试/重放辅助：清空去重记忆。 */
    public void reset() {
        acceptedEventIds.clear();
    }

    /** 拒绝原因便捷访问（供文档/测试引用）。 */
    public static RejectionReason[] rejectionReasons() {
        return RejectionReason.values();
    }
}
