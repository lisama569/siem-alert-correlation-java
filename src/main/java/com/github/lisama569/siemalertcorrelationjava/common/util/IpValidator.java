package com.github.lisama569.siemalertcorrelationjava.common.util;

import java.net.Inet6Address;
import java.net.InetAddress;

/** IP 地址语义校验（仅本地校验，无外部依赖，不触发任何 DNS 解析）。 */
public final class IpValidator {

    private IpValidator() {
    }

    /**
     * null/空表示字段未提供（视为合法，缺失不等于非法）；
     * 非空时必须是语义合法的 IPv4 或 IPv6。
     */
    public static boolean isValid(String ip) {
        if (ip == null || ip.isBlank()) {
            return true;
        }
        String value = ip.trim();
        return isIPv4(value) || isIPv6(value);
    }

    /** IPv4：4 段 0-255，不允许前导零以外的花活（允许单数字，不允许 256+）。 */
    static boolean isIPv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.chars().allMatch(Character::isDigit)) {
                return false;
            }
            int n = Integer.parseInt(part);
            if (n < 0 || n > 255) {
                return false;
            }
        }
        return true;
    }

    /** IPv6：借助 JDK 的字面量解析（禁止双 ::、非法段等），不做任何 DNS 查询。 */
    static boolean isIPv6(String value) {
        try {
            // InetAddress.getByName 对纯 IPv6 字面量直接解析，不会触发 DNS
            InetAddress addr = InetAddress.getByName(value);
            return addr instanceof Inet6Address && value.indexOf(':') >= 0;
        } catch (Exception e) {
            return false;
        }
    }
}
