package org.jetbrains.nativecerts.win32;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.StructLayout;

import static java.lang.foreign.MemoryLayout.paddingLayout;
import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

final class WinCryptStructures {
    static final StructLayout CERT_CONTEXT = structLayout(
            JAVA_INT.withName("dwCertEncodingType"), paddingLayout(4),
            ADDRESS.withName("pbCertEncoded"),
            JAVA_INT.withName("cbCertEncoded"), paddingLayout(4),
            ADDRESS.withName("pCertInfo"), ADDRESS.withName("hCertStore"));
    static final StructLayout CERT_ENHKEY_USAGE = structLayout(
            JAVA_INT.withName("cUsageIdentifier"), paddingLayout(4), ADDRESS.withName("rgpszUsageIdentifier"));
    static final StructLayout CERT_USAGE_MATCH = structLayout(
            JAVA_INT.withName("dwType"), paddingLayout(4), CERT_ENHKEY_USAGE.withName("Usage"));
    static final StructLayout CERT_CHAIN_PARA = structLayout(
            JAVA_INT.withName("cbSize"), paddingLayout(4), CERT_USAGE_MATCH.withName("RequestedUsage"));
    static final StructLayout CERT_CHAIN_POLICY_PARA = structLayout(
            JAVA_INT.withName("cbSize"), JAVA_INT.withName("dwFlags"), ADDRESS.withName("pvExtraPolicyPara"));
    static final StructLayout CERT_CHAIN_POLICY_STATUS = structLayout(
            JAVA_INT.withName("cbSize"), JAVA_INT.withName("dwError"),
            JAVA_INT.withName("lChainIndex"), JAVA_INT.withName("lElementIndex"), ADDRESS.withName("pvExtraPolicyStatus"));

    static long offset(MemoryLayout layout, String field) {
        return layout.byteOffset(MemoryLayout.PathElement.groupElement(field));
    }

    private WinCryptStructures() {
    }
}
