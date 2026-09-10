package org.jetbrains.nativecerts.win32;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import java.lang.foreign.Arena;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.jetbrains.nativecerts.win32.WinCryptStructures.*;
import static org.junit.Assert.assertEquals;

public class WinCryptStructuresTest {
    @BeforeClass
    public static void require64BitPointers() {
        Assume.assumeTrue(ADDRESS.byteSize() == 8);
    }

    @Test
    public void certificateContextMatchesWindowsAbi() {
        assertEquals(40, CERT_CONTEXT.byteSize());
        assertEquals(8, CERT_CONTEXT.byteAlignment());
        assertEquals(0, offset(CERT_CONTEXT, "dwCertEncodingType"));
        assertEquals(8, offset(CERT_CONTEXT, "pbCertEncoded"));
        assertEquals(16, offset(CERT_CONTEXT, "cbCertEncoded"));
        assertEquals(24, offset(CERT_CONTEXT, "pCertInfo"));
        assertEquals(32, offset(CERT_CONTEXT, "hCertStore"));
    }

    @Test
    public void chainParametersMatchWindowsAbi() {
        assertEquals(16, CERT_ENHKEY_USAGE.byteSize());
        assertEquals(8, offset(CERT_ENHKEY_USAGE, "rgpszUsageIdentifier"));
        assertEquals(24, CERT_USAGE_MATCH.byteSize());
        assertEquals(8, offset(CERT_USAGE_MATCH, "Usage"));
        assertEquals(32, CERT_CHAIN_PARA.byteSize());
        assertEquals(8, offset(CERT_CHAIN_PARA, "RequestedUsage"));
        assertEquals(8, CERT_CHAIN_PARA.byteAlignment());
    }

    @Test
    public void policyStructuresMatchWindowsAbi() {
        assertEquals(16, CERT_CHAIN_POLICY_PARA.byteSize());
        assertEquals(8, offset(CERT_CHAIN_POLICY_PARA, "pvExtraPolicyPara"));
        assertEquals(24, CERT_CHAIN_POLICY_STATUS.byteSize());
        assertEquals(4, offset(CERT_CHAIN_POLICY_STATUS, "dwError"));
        assertEquals(8, offset(CERT_CHAIN_POLICY_STATUS, "lChainIndex"));
        assertEquals(12, offset(CERT_CHAIN_POLICY_STATUS, "lElementIndex"));
        assertEquals(16, offset(CERT_CHAIN_POLICY_STATUS, "pvExtraPolicyStatus"));
    }

    @Test
    public void nativeStructuresStartZeroed() {
        try (var arena = Arena.ofConfined()) {
            var policy = arena.allocate(CERT_CHAIN_POLICY_PARA);
            assertEquals(0, policy.get(JAVA_INT, offset(CERT_CHAIN_POLICY_PARA, "dwFlags")));
            assertEquals(NULL, policy.get(ADDRESS, offset(CERT_CHAIN_POLICY_PARA, "pvExtraPolicyPara")));
            var chain = arena.allocate(CERT_CHAIN_PARA);
            for (int value : chain.toArray(JAVA_INT)) {
                assertEquals(0, value);
            }
        }
    }
}
