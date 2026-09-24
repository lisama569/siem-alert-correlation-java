package com.github.lisama569.siemalertcorrelationjava.tests.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 测试日志工具：统一打印输入、关键判定依据与最终状态。 */
public final class TestLogger {

    private static final Logger LOG = LoggerFactory.getLogger("SIEM-TEST");

    private TestLogger() {
    }

    public static void section(String title) {
        LOG.info("==== {} ====", title);
    }

    public static void input(String label, Object value) {
        LOG.info("[输入] {} = {}", label, value);
    }

    public static void basis(String label, Object value) {
        LOG.info("[判定依据] {} = {}", label, value);
    }

    public static void state(String label, Object value) {
        LOG.info("[最终状态] {} = {}", label, value);
    }

    public static void result(String label, Object value) {
        LOG.info("[结果] {} = {}", label, value);
    }
}
