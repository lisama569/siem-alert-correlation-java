package com.github.lisama569.siemalertcorrelationjava.ingest;

/**
 * 网络地址字面量校验（纯本地解析，不做 DNS 查询）。
 *
 * <p>支持：点分十进制 IPv4（每段 0-255，不允许前导零以外的非数字字符）、
 * 标准 IPv6（含 "::" 压缩与结尾内嵌 IPv4）。
 */
final class IpValidator {

    private IpValidator() {
    }

    static boolean isValid(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String v = value.trim();
        return isIpv4(v) || isIpv6(v);
    }

    private static boolean isIpv4(String v) {
        String[] parts = v.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(p) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv6(String v) {
        // 至多一个 "::" 压缩段
        int firstCompress = v.indexOf("::");
        if (firstCompress >= 0 && v.indexOf("::", firstCompress + 2) >= 0) {
            return false;
        }
        String head;
        String tail;
        boolean compressed = firstCompress >= 0;
        if (compressed) {
            head = v.substring(0, firstCompress);
            tail = v.substring(firstCompress + 2);
        } else {
            head = v;
            tail = "";
        }
        // 内嵌 IPv4 只允许出现在整个地址的最末位，因此压缩点之前的 head
        // 永远不允许出现点分段（如 "1.2.3.4::" 必须判非法）；tail 的最后一段允许。
        int headGroups = countGroups(head, false);
        int tailGroups = countGroups(tail, true);
        if (headGroups < 0 || tailGroups < 0) {
            return false;
        }
        if (compressed) {
            // "::" 至少压缩一个全零组
            return headGroups + tailGroups < 8;
        }
        return headGroups == 8;
    }

    /**
     * 返回合法组数；含非法组时返回 -1。
     *
     * @param allowEmbeddedV4 最后一组是否允许是内嵌 IPv4（按 2 组计）。
     *                        只有压缩点之后（地址最末位）才允许。
     */
    private static int countGroups(String s, boolean allowEmbeddedV4) {
        if (s.isEmpty()) {
            return 0;
        }
        String[] groups = s.split(":", -1);
        int count = 0;
        for (int i = 0; i < groups.length; i++) {
            String g = groups[i];
            if (g.isEmpty()) {
                return -1;
            }
            if (g.contains(".")) {
                // 内嵌 IPv4 只允许出现在整个地址的最后一组
                if (!allowEmbeddedV4 || i != groups.length - 1 || !isIpv4(g)) {
                    return -1;
                }
                count += 2;
                continue;
            }
            if (g.length() > 4) {
                return -1;
            }
            for (int j = 0; j < g.length(); j++) {
                char c = g.charAt(j);
                boolean hex = (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) {
                    return -1;
                }
            }
            count++;
        }
        return count;
    }
}
