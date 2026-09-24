package com.github.lisama569.siemalertcorrelationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleRegistry;
import com.github.lisama569.siemalertcorrelationjava.engine.correlation.RuleReplayer;
import com.github.lisama569.siemalertcorrelationjava.model.event.EventType;
import com.github.lisama569.siemalertcorrelationjava.model.event.SecurityEvent;
import com.github.lisama569.siemalertcorrelationjava.model.rule.CorrelationField;
import com.github.lisama569.siemalertcorrelationjava.model.rule.ReplayReport;
import com.github.lisama569.siemalertcorrelationjava.model.rule.RuleDefinition;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestFixtures;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestLogger;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 规则版本与复现测试：
 * 1) 同一序列以 v1(阈值5)/v2(阈值3) 重放，结论不同且各自确定；
 * 2) 同版本重复重放指纹完全一致；
 * 3) 规则注册不可变：同版本不同内容被拒绝；
 * 4) 版本不同指纹命名空间不同，规则变更不会让同一条件重复触发"同一个"告警。
 */
class RuleReplayTest {

    private SecurityEvent f(long offsetSec, String id) {
        return TestFixtures.loginFailed(TestFixtures.T0 + offsetSec * TestFixtures.SECOND, id, "alice");
    }

    private RuleDefinition rule(String version, int threshold) {
        return RuleDefinition.of("R-BRUTE", version, "暴力破解", EventType.LOGIN_FAILED,
                CorrelationField.USER, threshold, 60_000L, 5_000L, 15_000L, "HIGH");
    }

    private final List<SecurityEvent> sequence = List.of(
            f(0, "a"), f(5, "b"), f(10, "c"), f(14, "d"));

    @Test
    void replayIsVersionDeterminedAndReproducible() {
        TestLogger.section("RuleReplayTest.replayIsVersionDeterminedAndReproducible");
        RuleReplayer replayer = new RuleReplayer();
        RuleDefinition v1 = rule("v1", 5);
        RuleDefinition v2 = rule("v2", 3);

        ReplayReport rV1 = replayer.replay(v1, sequence);
        ReplayReport rV2a = replayer.replay(v2, sequence);
        ReplayReport rV2b = replayer.replay(v2, sequence);

        TestLogger.state("v1(阈值5) 触发数", rV1.firedCount());
        TestLogger.state("v2(阈值3) 触发数", rV2a.firedCount());
        TestLogger.state("v2 两次重放指纹", rV2a.fingerprints() + " == " + rV2b.fingerprints());

        assertEquals(0, rV1.firedCount(), "4 个事件达不到 v1 阈值 5");
        assertEquals(1, rV2a.firedCount());
        assertEquals(rV2a.fingerprints(), rV2b.fingerprints(), "重放必须可复现");
        assertTrue(rV2a.fingerprints().get(0).startsWith("R-BRUTE:v2|"));
    }

    @Test
    void ruleVersionIsImmutableAndLatestWins() {
        TestLogger.section("RuleReplayTest.ruleVersionIsImmutableAndLatestWins");
        RuleRegistry registry = new RuleRegistry();
        registry.register(rule("v1", 5));
        registry.register(rule("v2", 3));
        assertEquals(3, registry.latest("R-BRUTE").orElseThrow().threshold());
        assertEquals(5, registry.get("R-BRUTE", "v1").orElseThrow().threshold());

        boolean rejected = false;
        try {
            // 同版本不同内容必须拒绝
            registry.register(rule("v1", 9));
        } catch (IllegalArgumentException e) {
            rejected = true;
            TestLogger.basis("不可变注册被拒绝", e.getMessage());
        }
        assertTrue(rejected);
        TestLogger.state("最新版本阈值", registry.latest("R-BRUTE").orElseThrow().threshold());
    }

    @Test
    void differentRuleVersionsProduceDifferentFingerprintNamespaces() {
        TestLogger.section("RuleReplayTest.differentRuleVersionsProduceDifferentFingerprintNamespaces");
        // 构造两个版本都能触发的序列（6 个事件），验证其指纹前缀按版本隔离
        List<SecurityEvent> six = List.of(
                f(0, "a"), f(5, "b"), f(10, "c"), f(14, "d"),
                f(40, "e"), f(45, "g"), f(50, "h"));
        RuleReplayer replayer = new RuleReplayer();
        ReplayReport v1 = replayer.replay(rule("v1", 3), six);
        ReplayReport v2 = replayer.replay(rule("v2", 3), six);
        TestLogger.state("v1 指纹", v1.fingerprints());
        TestLogger.state("v2 指纹", v2.fingerprints());
        // 版本是指纹的一部分 → 即使条件相同也是不同命名空间，不会被当成同一条件重复触发旧告警
        assertNotEquals(v1.fingerprints(), v2.fingerprints());
        assertTrue(v1.fingerprints().stream().allMatch(x -> x.startsWith("R-BRUTE:v1|")));
    }
}
