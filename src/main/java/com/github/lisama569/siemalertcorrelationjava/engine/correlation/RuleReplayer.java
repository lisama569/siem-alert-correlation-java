package com.github.lisama569.siemalertcorrelationjava.engine.correlation;

import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.FireOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.rule.LateDecision;
import com.github.lisama569.siemalertcorrelationjava.model.rule.ReplayReport;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 规则重放器。
 * 以指定的、不可变的规则版本，按给定到达顺序重放历史事件序列；
 * 每次重放使用全新的临时引擎状态与独立时钟，因此：
 * <ul>
 *   <li>结论只取决于规则版本 + 事件序列（含到达顺序），确定且可复现；</li>
 *   <li>不写入实时引擎状态、不创建告警，对线上无副作用。</li>
 * </ul>
 */
@Service
public class RuleReplayer {

    private static final Logger log = LoggerFactory.getLogger(RuleReplayer.class);

    public ReplayReport replay(RuleDefinition rule, List<SecurityEvent> eventsInArrivalOrder) {
        // 临时注册表 + 临时引擎，保证隔离
        RuleRegistry tempRegistry = new RuleRegistry();
        tempRegistry.register(rule);
        CorrelationEngine tempEngine = new CorrelationEngine(tempRegistry);

        List<FireOutcome> outcomes = new ArrayList<>();
        Set<String> fingerprints = new LinkedHashSet<>();
        int fired = 0;
        int duplicate = 0;
        int rejectedLate = 0;

        // 重放时钟：随到达顺序取"已观测事件时间最大值"，等价于纯事件时间水位线，
        // 不带处理时间下界，保证同序列重放结论完全一致。
        long runningMax = 0L;

        for (SecurityEvent event : eventsInArrivalOrder) {
            runningMax = Math.max(runningMax, event.eventTime());
            FireOutcome outcome = tempEngine.processWith(rule, event, runningMax);
            outcomes.add(outcome);
            if (outcome.fired()) {
                fired++;
                fingerprints.add(outcome.fingerprint());
            }
            if (outcome.suppressedDuplicate()) {
                duplicate++;
            }
            if (outcome.lateDecision() == LateDecision.REJECTED_TOO_LATE) {
                rejectedLate++;
            }
        }
        log.info("规则重放完成 rule={} 输入={} 触发={} 重复抑制={} 过迟丢弃={} 指纹={}",
                rule.key(), eventsInArrivalOrder.size(), fired, duplicate, rejectedLate, fingerprints);
        return new ReplayReport(rule.ruleId(), rule.version(), eventsInArrivalOrder.size(),
                fired, duplicate, rejectedLate, List.copyOf(outcomes), List.copyOf(fingerprints));
    }
}
