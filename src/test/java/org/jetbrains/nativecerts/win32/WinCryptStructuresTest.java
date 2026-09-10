package org.jetbrains.nativecerts.win32;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.jetbrains.nativecerts.win32.WinCryptStructures.*;
import static org.junit.Assert.assertEquals;

/**
 * Pins the structure layouts to the sizes/offsets of the 64-bit Windows ABI (values from {@code sizeof}/{@code offsetof}
 * with MSVC, and identical to what JNA computed for its {@code WinCrypt} structures). Runs on any 64-bit OS.
 */
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
    public void chainContextMatchesWindowsAbi() {
        assertEquals(8, CERT_TRUST_STATUS.byteSize());
        assertEquals(16, GUID.byteSize());
        assertEquals(72, CERT_CHAIN_CONTEXT.byteSize());
        assertEquals(8, CERT_CHAIN_CONTEXT.byteAlignment());
        assertEquals(0, offset(CERT_CHAIN_CONTEXT, "cbSize"));
        assertEquals(4, offset(CERT_CHAIN_CONTEXT, "TrustStatus"));
        assertEquals(12, offset(CERT_CHAIN_CONTEXT, "cChain"));
        assertEquals(16, offset(CERT_CHAIN_CONTEXT, "rgpChain"));
        assertEquals(24, offset(CERT_CHAIN_CONTEXT, "cLowerQualityChainContext"));
        assertEquals(32, offset(CERT_CHAIN_CONTEXT, "rgpLowerQualityChainContext"));
        assertEquals(40, offset(CERT_CHAIN_CONTEXT, "fHasRevocationFreshnessTime"));
        assertEquals(44, offset(CERT_CHAIN_CONTEXT, "dwRevocationFreshnessTime"));
        assertEquals(48, offset(CERT_CHAIN_CONTEXT, "dwCreateFlags"));
        assertEquals(52, offset(CERT_CHAIN_CONTEXT, "ChainId"));
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
        // Crypt32ExtUtil relies on Arena.allocate zero-filling the structures (NULL pointers, zero counts)
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment policy = arena.allocate(CERT_CHAIN_POLICY_PARA);
            assertEquals(0, policy.get(JAVA_INT, offset(CERT_CHAIN_POLICY_PARA, "dwFlags")));
            assertEquals(NULL, policy.get(ADDRESS, offset(CERT_CHAIN_POLICY_PARA, "pvExtraPolicyPara")));
            MemorySegment chain = arena.allocate(CERT_CHAIN_PARA);
            for (int value : chain.toArray(JAVA_INT)) {
                assertEquals(0, value);
            }
        }
    }
}
