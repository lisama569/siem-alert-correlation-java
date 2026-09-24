package com.github.lisama569.siemalertcorrelationjava.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 基础 Bean 配置：统一使用可注入的时钟，保证测试确定性。 */
@Configuration
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
