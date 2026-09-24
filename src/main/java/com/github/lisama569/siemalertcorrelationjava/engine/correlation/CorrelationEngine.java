package com.github.lisama569.siemalertcorrelationjava.engine.correlation;

import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.CorrelationField;
import com.github.lisama569.siemalertcorrelationjava.model.rule.FireOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.rule.LateDecision;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 关联检测引擎（有状态）。每个规则版本持有独立、互不影响的状态。
 *
 * <p>乱序/迟到语义（确定性）：
 * <ul>
 *   <li>水位线 watermark = 已观测最大事件时间 − allowedLatenessMs，且单调不减
 *       （纯事件时间语义，实时处理与历史重放使用完全相同的判定）。</li>
 *   <li>eventTime ≥ watermark：ON_TIME，正常参与判定；</li>
 *   <li>eventTime &lt; watermark 但 ≥ watermark − allowedLateness：
 *       ACCEPTED_WITHIN_LATENESS，仍参与判定；容忍范围内任意乱序到达，最终触发结论一致。</li>
 *   <li>eventTime &lt; watermark − allowedLateness：REJECTED_TOO_LATE，确定丢弃并可解释。</li>
 * </ul>
 *
 * <p>触发语义：同类型事件按 {@link CorrelationField} 归并；关联键内事件按事件时间排序，
 * 以 maxGapMs 切分为会话（相邻间隔超过 maxGap 即新会话）；会话内事件数达到 threshold 触发一次。
 * 触发锚点 = 会话内首条事件（事件时间最小、并列取 eventId 最小），指纹基于锚点，
 * 因而同一会话条件在乱序补全时不会重复触发；规则新版本是新指纹命名空间，只对新条件触发。
 */
@Service
public class CorrelationEngine {

    private static final Logger log = LoggerFactory.getLogger(CorrelationEngine.class);

    private final RuleRegistry registry;
    private final Map<String, RuleState> states = new ConcurrentHashMap<>();

    public CorrelationEngine(RuleRegistry registry) {
        this.registry = registry;
    }

    /** 向所有生效规则（每个 ruleId 的最新版本）喂入一个事件。 */
    public List<FireOutcome> process(SecurityEvent event, long nowMs) {
        List<FireOutcome> results = new ArrayList<>();
        for (RuleDefinition rule : registry.latestVersions()) {
            results.add(processWith(rule, event, nowMs));
        }
        return results;
    }

    /** 向指定（不可变的）规则版本喂入事件；不匹配的事件返回 ON_TIME 且不触发。 */
    public FireOutcome processWith(RuleDefinition rule, SecurityEvent event, long nowMs) {
        RuleState state = states.computeIfAbsent(rule.key(), k -> new RuleState(rule));
        synchronized (state) {
            return state.accept(event, nowMs);
        }
    }

    /** 全部规则中的最小水位线（测试/可观测用）。 */
    public long watermark() {
        return states.values().stream()
                .mapToLong(s -> {
                    synchronized (s) {
                        return s.watermark;
                    }
                })
                .min().orElse(0L);
    }

    /** 测试辅助：清空全部规则状态（注册信息保留）。 */
    public void reset() {
        states.clear();
    }

    /** 单规则版本的检测状态。包私有以便测试直接观测。 */
    static final class RuleState {
        private final RuleDefinition rule;
        private final Map<String, Bucket> buckets = new LinkedHashMap<>();
        private long maxEventTime = Long.MIN_VALUE;
        private long watermark = 0L;

        RuleState(RuleDefinition rule) {
            this.rule = rule;
        }

        FireOutcome accept(SecurityEvent event, long nowMs) {
            String ck = rule.correlationKeyOf(event);
            // 纯事件时间水位线：watermark = maxEventTime − lateness，单调不减。
            // nowMs 仅用于记录处理时间语义，不参与水位线，保证实时与重放判定一致。
            if (event.eventTime() > maxEventTime) {
                maxEventTime = event.eventTime();
            }
            long candidateWm = Math.max(maxEventTime - rule.allowedLatenessMs(), 0L);
            if (candidateWm > watermark) {
                watermark = candidateWm;
            }

            if (!rule.matches(event)) {
                return new FireOutcome(rule.key(), ck, false, false, null,
                        LateDecision.ON_TIME, watermark, List.of());
            }

            // 迟到判定：事件时间早于水位线即属迟到；早于水位线减去容忍则过迟丢弃。
            LateDecision late;
            if (event.eventTime() >= watermark) {
                late = LateDecision.ON_TIME;
            } else if (event.eventTime() >= watermark - rule.allowedLatenessMs()) {
                late = LateDecision.ACCEPTED_WITHIN_LATENESS;
            } else {
                log.info("事件过迟被丢弃 rule={} eventId={} eventTime={} watermark={}",
                        rule.key(), event.eventId(), event.eventTime(), watermark);
                return new FireOutcome(rule.key(), ck, false, false, null,
                        LateDecision.REJECTED_TOO_LATE, watermark, List.of());
            }

            Bucket bucket = buckets.computeIfAbsent(ck, k -> new Bucket());
            // 幂等：同一事件重复喂入（理论上接入层已拦，这里双保险）
            boolean added = bucket.eventIds.add(event.eventId());
            if (added) {
                bucket.events.add(event);
            }
            pruneExpired(bucket);
            FireOutcome outcome = evaluateCluster(bucket, ck, late, event.eventId());
            log.debug("规则判定 rule={} ck={} eventId={} late={} fired={} wm={}",
                    rule.key(), ck, event.eventId(), late, outcome.fired(), watermark);
            return outcome;
        }

        /** 归档不可能再被迟到事件影响的老事件：eventTime &lt; watermark - window。 */
        private void pruneExpired(Bucket bucket) {
            long boundary = watermark - rule.windowMs();
            bucket.events.removeIf(e -> e.eventTime() < boundary);
        }

        /**
         * 基于事件时间的会话聚类：排序后按 maxGap 切分会话，逐会话结算。
         * 规则：
         * <ul>
         *   <li>会话事件数 &lt; threshold：不触发；</li>
         *   <li>会话达标且锚点指纹未触发过：触发一次并记录指纹；</li>
         *   <li>会话达标但锚点指纹已记录（含迟到事件把已触发会话向前扩张的情况）：
         *       只返回 suppressedDuplicate，绝不重复触发。</li>
         * </ul>
         * 为避免"其他关联键/旧会话触发"污染本次输入的判定，仅返回包含当前输入事件的会话结论。
         */
        private FireOutcome evaluateCluster(Bucket bucket, String ck, LateDecision late,
                                            String inputEventId) {
            List<SecurityEvent> sorted = bucket.events.stream()
                    .sorted(Comparator.comparingLong(SecurityEvent::eventTime)
                            .thenComparing(SecurityEvent::eventId))
                    .toList();

            FireOutcome sessionResult =
                    new FireOutcome(rule.key(), ck, false, false, null, late, watermark, List.of());
            List<SecurityEvent> session = new ArrayList<>();
            for (int i = 0; i <= sorted.size(); i++) {
                boolean boundary = i == sorted.size()
                        || (i > 0 && sorted.get(i).eventTime() - sorted.get(i - 1).eventTime() > rule.maxGapMs());
                if (boundary && !session.isEmpty()) {
                    boolean containsInput = session.stream().anyMatch(e -> e.eventId().equals(inputEventId));
                    FireOutcome r = settleSession(bucket, ck, session, late);
                    if (containsInput) {
                        sessionResult = r;
                    }
                    session = new ArrayList<>();
                }
                if (i < sorted.size()) {
                    session.add(sorted.get(i));
                }
            }
            return sessionResult;
        }

        private FireOutcome settleSession(Bucket bucket, String ck, List<SecurityEvent> session,
                                          LateDecision late) {
            if (session.size() < rule.threshold()) {
                return new FireOutcome(rule.key(), ck, false, false, null, late, watermark, List.of());
            }
            SecurityEvent anchor = session.get(0);
            String fingerprint = fingerprint(ck, anchor);
            // 抑制条件：锚点指纹已记录，或会话包含任何已参与过触发的事件
            // （覆盖"容忍范围内的迟到事件把已触发会话向前扩张、锚点前移"的情形）。
            boolean alreadyFired = bucket.firedFingerprints.contains(fingerprint)
                    || session.stream().anyMatch(e -> bucket.firedEventIds.contains(e.eventId()));
            if (alreadyFired) {
                return new FireOutcome(rule.key(), ck, false, true, fingerprint,
                        late, watermark, List.copyOf(session));
            }
            bucket.firedFingerprints.add(fingerprint);
            session.forEach(e -> bucket.firedEventIds.add(e.eventId()));
            log.info("规则触发 rule={} ck={} fingerprint={} 会话事件数={} 锚点={}@{}",
                    rule.key(), ck, fingerprint, session.size(), anchor.eventId(), anchor.eventTime());
            return new FireOutcome(rule.key(), ck, true, false, fingerprint,
                    late, watermark, List.copyOf(session));
        }

        private String fingerprint(String ck, SecurityEvent anchor) {
            return rule.key() + "|" + ck + "|" + anchor.eventId();
        }
    }

    /** 关联键桶：事件集合、触发指纹记忆与已参与触发的事件记忆。 */
    static final class Bucket {
        final List<SecurityEvent> events = new ArrayList<>();
        final java.util.Set<String> eventIds = ConcurrentHashMap.newKeySet();
        final java.util.Set<String> firedFingerprints = ConcurrentHashMap.newKeySet();
        final java.util.Set<String> firedEventIds = ConcurrentHashMap.newKeySet();
    }
}
