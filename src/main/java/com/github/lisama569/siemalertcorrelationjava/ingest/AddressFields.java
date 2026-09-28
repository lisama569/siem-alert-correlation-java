package com.github.lisama569.siemalertcorrelationjava.ingest;

import java.util.Set;

/**
 * 网络地址属性名的识别（命名风格无关）。
 *
 * <p>同一个地址含义的字段在不同来源里可能写成不同风格，
 * 例如 {@code srcIp}、{@code SRCIP}、{@code src_ip}、{@code src-ip}、
 * {@code Src_IP} 都应被识别为源地址。识别时先把属性名归一化：
 * 转小写并剔除 {@code _}、{@code -} 分隔符，再与规范名集合比较。
 * 因此 {@code user}、{@code host}、{@code hostname}、{@code srcPort}
 * 等非地址属性不会被当成地址校验。
 */
final class AddressFields {

    /** 归一化后的网络地址属性规范名集合。 */
    private static final Set<String> CANONICAL_KEYS = Set.of(
            "ip", "srcip", "dstip", "sourceip", "destinationip");

    private AddressFields() {
    }

    /** 该属性名是否表示网络地址（大小写、下划线、连字符风格无关）。 */
    static boolean isAddressField(String key) {
        return key != null && CANONICAL_KEYS.contains(canonicalize(key));
    }

    /** 转小写并剔除下划线 / 连字符分隔符。 */
    private static String canonicalize(String key) {
        StringBuilder sb = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c != '_' && c != '-') {
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString();
    }
}
