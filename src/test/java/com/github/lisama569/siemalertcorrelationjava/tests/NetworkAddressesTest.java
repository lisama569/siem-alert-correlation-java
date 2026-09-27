package com.github.lisama569.siemalertcorrelationjava.tests;

import com.github.lisama569.siemalertcorrelationjava.ingest.support.NetworkAddresses;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetworkAddressesTest {

    @Test
    void recognizesAddressFieldNames() {
        assertTrue(NetworkAddresses.isAddressField("srcIp"));
        assertTrue(NetworkAddresses.isAddressField("dst_ip"));
        assertTrue(NetworkAddresses.isAddressField("clientIpAddress"));
        assertTrue(NetworkAddresses.isAddressField("IPV6"));
        assertTrue(NetworkAddresses.isAddressField("source-ip"));
        // 含 ip 但不是网络地址字段，不得误判
        assertFalse(NetworkAddresses.isAddressField("zip"));
        assertFalse(NetworkAddresses.isAddressField("description"));
        assertFalse(NetworkAddresses.isAddressField("script"));
        assertFalse(NetworkAddresses.isAddressField("host"));
        assertFalse(NetworkAddresses.isAddressField(null));
    }

    @Test
    void acceptsValidIPv4AndIPv6() {
        assertTrue(NetworkAddresses.isValidLiteral("192.168.0.1"));
        assertTrue(NetworkAddresses.isValidLiteral("10.0.0.255"));
        assertTrue(NetworkAddresses.isValidLiteral("0.0.0.0"));
        assertTrue(NetworkAddresses.isValidLiteral("255.255.255.255"));
        assertTrue(NetworkAddresses.isValidLiteral("2001:db8::1"));
        assertTrue(NetworkAddresses.isValidLiteral("::1"));
        assertTrue(NetworkAddresses.isValidLiteral("fe80::1"));
        assertTrue(NetworkAddresses.isValidLiteral("2001:db8:0:0:0:0:0:1"));
        assertTrue(NetworkAddresses.isValidLiteral("2001:db8::192.0.2.1"));
        assertTrue(NetworkAddresses.isValidLiteral("::ffff:192.0.2.1"));
    }

    @Test
    void rejectsInvalidLiterals() {
        // null / 空白
        assertFalse(NetworkAddresses.isValidLiteral(null));
        assertFalse(NetworkAddresses.isValidLiteral("   "));
        // IPv4
        assertFalse(NetworkAddresses.isValidLiteral("256.0.0.1"), "段超 255");
        assertFalse(NetworkAddresses.isValidLiteral("1.2.3"), "段数不足");
        assertFalse(NetworkAddresses.isValidLiteral("1.2.3.4.5"), "段数过多");
        assertFalse(NetworkAddresses.isValidLiteral("01.2.3.4"), "前导零");
        assertFalse(NetworkAddresses.isValidLiteral("a.b.c.d"), "非数字");
        assertFalse(NetworkAddresses.isValidLiteral("example.com"), "不得做 DNS/域名解析");
        // IPv6
        assertFalse(NetworkAddresses.isValidLiteral("2001::1::8"), "多个压缩");
        assertFalse(NetworkAddresses.isValidLiteral("2001:db8:::1"), "孤立空段");
        assertFalse(NetworkAddresses.isValidLiteral("gggg::1"), "非十六进制");
        assertFalse(NetworkAddresses.isValidLiteral("2001:db8:0:0:0:0:0:0:1"), "9 段");
        assertFalse(NetworkAddresses.isValidLiteral("2001:db8:0:0:0:0:0"), "7 段无压缩");
        assertFalse(NetworkAddresses.isValidLiteral("2001:db8::300.0.0.1"), "嵌入 IPv4 段超范围");
        assertFalse(NetworkAddresses.isValidLiteral("not-an-ip"));
    }
}
