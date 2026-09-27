package com.github.lisama569.siemalertcorrelationjava.ingest.support;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 网络地址字面量校验（纯本地实现，不做任何 DNS 查询）。
 *
 * <p>判定属性中表示网络地址的字段（如 {@code srcIp} / {@code dst_ip} /
 * {@code clientIpAddress}）的值是否为合法的 IPv4/IPv6 字面量。
 */
public final class NetworkAddresses {

    private NetworkAddresses() {
    }

    /**
     * 字段名是否表示网络地址。
     *
     * <p>规则（确定性，与大小写、驼峰/下划线风格无关）：先把驼峰边界与下划线/连字符
     * 切分成小写 token，只要 token 序列中出现 {@code ip}/{@code ipv4}/{@code ipv6}
     * 之一，即视为网络地址字段。因此 {@code srcIp}、{@code dst_ip}、
     * {@code clientIpAddress}、{@code IPV6} 都会命中，而 {@code zip}、
     * {@code description}、{@code team_zip} 不会误判。
     */
    public static boolean isAddressField(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        for (String token : tokenize(key)) {
            if (token.equals("ip") || token.equals("ipv4") || token.equals("ipv6")) {
                return true;
            }
        }
        return false;
    }

    /** 值是否为合法的 IPv4/IPv6 字面量；空白与 null 返回 false。 */
    public static boolean isValidLiteral(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String s = value.trim();
        return isValidIPv4(s) || isValidIPv6(s);
    }

    private static List<String> tokenize(String key) {
        // 在驼峰边界插入分隔符：aB -> a-B，随后按非字母数字切分并转小写
        String separated = key.replaceAll("([a-z0-9])([A-Z])", "$1-$2")
                .replaceAll("([A-Z]+)([A-Z][a-z])", "$1-$2");
        List<String> tokens = new ArrayList<>();
        for (String part : separated.split("[^a-zA-Z0-9]+")) {
            if (!part.isEmpty()) {
                tokens.add(part.toLowerCase(Locale.ROOT));
            }
        }
        return tokens;
    }

    /** 严格 IPv4：恰好 4 个十进制段，每段 0-255，除单个 0 外不允许前导零。 */
    static boolean isValidIPv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3 || !p.chars().allMatch(Character::isDigit)) {
                return false;
            }
            if (p.length() > 1 && p.charAt(0) == '0') {
                return false; // 拒绝 01.02.03.04 这类非规范写法
            }
            int v = Integer.parseInt(p);
            if (v > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * IPv6 校验：至多一个 {@code ::} 压缩，展开后恰好 8 个 1-4 位十六进制段；
     * 允许末 32 位为嵌入的 IPv4 字面量（如 2001:db8::192.0.2.1）。
     */
    static boolean isValidIPv6(String s) {
        if (s.indexOf(':') < 0) {
            return false;
        }
        String normalized = s;
        // 若存在嵌入的 IPv4 末段，替换为两个十六进制组后统一校验
        int lastColon = s.lastIndexOf(':');
        if (lastColon >= 0 && s.indexOf('.', lastColon) >= 0) {
            String v4 = s.substring(lastColon + 1);
            if (!isValidIPv4(v4)) {
                return false;
            }
            normalized = s.substring(0, lastColon + 1) + "0:0";
        }
        // 只允许出现十六进制字符与冒号
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F') || c == ':';
            if (!ok) {
                return false;
            }
        }

        int compression = countOccurrences(normalized, "::");
        if (compression > 1) {
            return false; // "2001::1::8"
        }
        if (compression == 1) {
            String[] halves = normalized.split("::", -1);
            if (halves.length != 2) {
                return false;
            }
            int left = countHexGroups(halves[0]);
            int right = countHexGroups(halves[1]);
            // 任一半出现孤立空段（如 "2001:::1"）即非法；显式段满 8 则不需要压缩
            return left >= 0 && right >= 0 && left + right <= 7;
        }
        return countHexGroups(normalized) == 8;
    }

    /**
     * 统计冒号分隔的十六进制组数。
     *
     * @return 合法时返回组数（空串返回 0，表示压缩边界）；出现空段或非十六进制段时返回 -1
     */
    private static int countHexGroups(String part) {
        if (part.isEmpty()) {
            return 0;
        }
        String[] groups = part.split(":", -1);
        int count = 0;
        for (String g : groups) {
            if (g.isEmpty() || g.length() > 4
                    || !g.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
                return -1;
            }
            count++;
        }
        return count;
    }

    private static int countOccurrences(String s, String token) {
        int count = 0;
        int idx = 0;
        while ((idx = s.indexOf(token, idx)) >= 0) {
            count++;
            idx += token.length();
        }
        return count;
    }
}
