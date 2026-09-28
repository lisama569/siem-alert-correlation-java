package com.github.lisama569.siemalertcorrelationjava.ingest;

import java.util.Set;
import java.util.TreeSet;

/**
 * 判断某个属性名是否表示网络地址（命名风格无关的精确归一匹配）。
 *
 * <p>识别口径（与命名风格无关）：先把属性名归一化为小写并去掉风格分隔符
 * （下划线 {@code _}、连字符 {@code -}、点 {@code .} 与空白），再与固定的
 * <b>规范地址字段名集合</b>做精确匹配。这样不同来源各自的写法——例如
 * {@code srcIp} / {@code src_ip} / {@code SRC-IP} / {@code src.ip}——都会被
 * 识别为同一个地址字段；而 {@code user}、{@code host}、{@code hostname}、
 * {@code script} 这类<b>不表示地址</b>的普通属性不在集合内，绝不做地址校验。
 *
 * <p>采用"归一后精确命中集合"而不是"包含 ip 子串"，是为了避免
 * {@code host}、{@code script}、{@code description} 之类字段被误判为地址。
 */
final class IpFieldMatcher {

    /** 规范名 = 语义前缀 + 地址后缀（"ip" 或 "ipaddress"）的全部组合。 */
    static final Set<String> CANONICAL_IP_FIELD_NAMES;

    static {
        String[] prefixes = {
                "", "src", "dst", "source", "destination",
                "client", "server", "remote", "local", "orig", "resp"
        };
        String[] suffixes = {"ip", "ipaddress"};
        TreeSet<String> names = new TreeSet<>();
        for (String prefix : prefixes) {
            for (String suffix : suffixes) {
                names.add(prefix + suffix);
            }
        }
        CANONICAL_IP_FIELD_NAMES = Set.copyOf(names);
    }

    private IpFieldMatcher() {
    }

    /**
     * 该属性名是否表示一个网络地址字段。
     *
     * @param key 原始属性名，null 视为非地址字段
     */
    static boolean isIpAddressField(String key) {
        if (key == null) {
            return false;
        }
        return CANONICAL_IP_FIELD_NAMES.contains(normalize(key));
    }

    /** 小写化并去除命名风格分隔符（_ - . 及空白）。 */
    static String normalize(String key) {
        StringBuilder sb = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c == '_' || c == '-' || c == '.' || Character.isWhitespace(c)) {
                continue;
            }
            sb.append(Character.toLowerCase(c));
        }
        return sb.toString();
    }
}
