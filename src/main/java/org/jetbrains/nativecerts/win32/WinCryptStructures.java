package org.jetbrains.nativecerts.win32;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.StructLayout;

import static java.lang.foreign.MemoryLayout.paddingLayout;
import static java.lang.foreign.MemoryLayout.sequenceLayout;
import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * Memory layouts of the {@code wincrypt.h} structures used by {@link Crypt32ExtUtil}, replacing JNA's
 * {@code WinCrypt.*} {@code Structure} classes.
 * <p>
 * The layouts hard-code the 64-bit Windows ABI (x64 and ARM64): pointers are 8 bytes and 8-byte aligned,
 * {@code DWORD}/{@code BOOL}/{@code LONG} are 4 bytes, so a {@code DWORD} followed by a pointer needs 4 bytes of
 * explicit padding. 32-bit Windows is not supported (see the static initializer). Offsets and sizes are asserted
 * in {@code WinCryptStructuresTest}.
 */
@SuppressWarnings("SpellCheckingInspection")
final class WinCryptStructures {
    private WinCryptStructures() {
    }

    static {
        if (ADDRESS.byteSize() != 8) {
            throw new UnsupportedOperationException(
                    "Native structure layouts are defined for 64-bit Windows only, pointer size is " + ADDRESS.byteSize());
        }
    }

    /**
     * <pre>
     * typedef struct _CERT_CONTEXT {
     *   DWORD      dwCertEncodingType;
     *   BYTE       *pbCertEncoded;
     *   DWORD      cbCertEncoded;
     *   PCERT_INFO pCertInfo;
     *   HCERTSTORE hCertStore;
     * } CERT_CONTEXT, *PCERT_CONTEXT;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context">MSDN</a>
     */
    static final StructLayout CERT_CONTEXT = structLayout(
            JAVA_INT.withName("dwCertEncodingType"),
            paddingLayout(4),
            ADDRESS.withName("pbCertEncoded"),
            JAVA_INT.withName("cbCertEncoded"),
            paddingLayout(4),
            ADDRESS.withName("pCertInfo"),
            ADDRESS.withName("hCertStore")
    ).withName("CERT_CONTEXT");

    /**
     * <pre>
     * typedef struct _CTL_USAGE {   // a.k.a. CERT_ENHKEY_USAGE
     *   DWORD  cUsageIdentifier;
     *   LPSTR  *rgpszUsageIdentifier;
     * } CTL_USAGE, *PCTL_USAGE, CERT_ENHKEY_USAGE, *PCERT_ENHKEY_USAGE;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-ctl_usage">MSDN</a>
     */
    static final StructLayout CERT_ENHKEY_USAGE = structLayout(
            JAVA_INT.withName("cUsageIdentifier"),
            paddingLayout(4),
            ADDRESS.withName("rgpszUsageIdentifier")
    ).withName("CERT_ENHKEY_USAGE");

    /**
     * <pre>
     * typedef struct _CERT_USAGE_MATCH {
     *   DWORD             dwType;   // USAGE_MATCH_TYPE_AND / USAGE_MATCH_TYPE_OR
     *   CERT_ENHKEY_USAGE Usage;
     * } CERT_USAGE_MATCH, *PCERT_USAGE_MATCH;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_usage_match">MSDN</a>
     */
    static final StructLayout CERT_USAGE_MATCH = structLayout(
            JAVA_INT.withName("dwType"),
            paddingLayout(4),
            CERT_ENHKEY_USAGE.withName("Usage")
    ).withName("CERT_USAGE_MATCH");

    /**
     * Chain-building parameters for {@code CertGetCertificateChain}. Only the mandatory part of the structure is
     * declared (the optional {@code CERT_CHAIN_PARA_HAS_EXTRA_FIELDS} members are omitted, as in JNA);
     * {@code cbSize} must be set to the size of this layout.
     * <pre>
     * typedef struct _CERT_CHAIN_PARA {
     *   DWORD            cbSize;
     *   CERT_USAGE_MATCH RequestedUsage;
     * } CERT_CHAIN_PARA, *PCERT_CHAIN_PARA;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_para">MSDN</a>
     */
    static final StructLayout CERT_CHAIN_PARA = structLayout(
            JAVA_INT.withName("cbSize"),
            paddingLayout(4),
            CERT_USAGE_MATCH.withName("RequestedUsage")
    ).withName("CERT_CHAIN_PARA");

    /**
     * <pre>
     * typedef struct _CERT_TRUST_STATUS {
     *   DWORD dwErrorStatus;
     *   DWORD dwInfoStatus;
     * } CERT_TRUST_STATUS, *PCERT_TRUST_STATUS;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status">MSDN</a>
     */
    static final StructLayout CERT_TRUST_STATUS = structLayout(
            JAVA_INT.withName("dwErrorStatus"),
            JAVA_INT.withName("dwInfoStatus")
    ).withName("CERT_TRUST_STATUS");

    /**
     * <pre>
     * typedef struct _GUID {
     *   unsigned long  Data1;
     *   unsigned short Data2;
     *   unsigned short Data3;
     *   unsigned char  Data4[8];
     * } GUID;
     * </pre>
     */
    static final StructLayout GUID = structLayout(
            JAVA_INT.withName("Data1"),
            JAVA_SHORT.withName("Data2"),
            JAVA_SHORT.withName("Data3"),
            sequenceLayout(8, JAVA_BYTE).withName("Data4")
    ).withName("GUID");

    /**
     * Result of {@code CertGetCertificateChain}. We only read {@code cbSize} to verify that the structure returned by
     * the OS has the size we expect (the same sanity check JNA's {@code Structure.size()} comparison did).
     * <pre>
     * typedef struct _CERT_CHAIN_CONTEXT {
     *   DWORD                cbSize;
     *   CERT_TRUST_STATUS    TrustStatus;
     *   DWORD                cChain;
     *   PCERT_SIMPLE_CHAIN   *rgpChain;
     *   DWORD                cLowerQualityChainContext;
     *   PCCERT_CHAIN_CONTEXT *rgpLowerQualityChainContext;
     *   BOOL                 fHasRevocationFreshnessTime;
     *   DWORD                dwRevocationFreshnessTime;
     *   DWORD                dwCreateFlags;
     *   GUID                 ChainId;
     * } CERT_CHAIN_CONTEXT, *PCERT_CHAIN_CONTEXT;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_context">MSDN</a>
     */
    static final StructLayout CERT_CHAIN_CONTEXT = structLayout(
            JAVA_INT.withName("cbSize"),
            CERT_TRUST_STATUS.withName("TrustStatus"),
            JAVA_INT.withName("cChain"),
            ADDRESS.withName("rgpChain"),
            JAVA_INT.withName("cLowerQualityChainContext"),
            paddingLayout(4),
            ADDRESS.withName("rgpLowerQualityChainContext"),
            JAVA_INT.withName("fHasRevocationFreshnessTime"),
            JAVA_INT.withName("dwRevocationFreshnessTime"),
            JAVA_INT.withName("dwCreateFlags"),
            GUID.withName("ChainId"),
            paddingLayout(4)
    ).withName("CERT_CHAIN_CONTEXT");

    /**
     * <pre>
     * typedef struct _CERT_CHAIN_POLICY_PARA {
     *   DWORD cbSize;
     *   DWORD dwFlags;
     *   void  *pvExtraPolicyPara;
     * } CERT_CHAIN_POLICY_PARA, *PCERT_CHAIN_POLICY_PARA;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_para">MSDN</a>
     */
    static final StructLayout CERT_CHAIN_POLICY_PARA = structLayout(
            JAVA_INT.withName("cbSize"),
            JAVA_INT.withName("dwFlags"),
            ADDRESS.withName("pvExtraPolicyPara")
    ).withName("CERT_CHAIN_POLICY_PARA");

    /**
     * <pre>
     * typedef struct _CERT_CHAIN_POLICY_STATUS {
     *   DWORD cbSize;
     *   DWORD dwError;          // 0 if the chain satisfies the policy, otherwise e.g. CERT_E_UNTRUSTEDROOT
     *   LONG  lChainIndex;
     *   LONG  lElementIndex;
     *   void  *pvExtraPolicyStatus;
     * } CERT_CHAIN_POLICY_STATUS, *PCERT_CHAIN_POLICY_STATUS;
     * </pre>
     *
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_status">MSDN</a>
     */
    static final StructLayout CERT_CHAIN_POLICY_STATUS = structLayout(
            JAVA_INT.withName("cbSize"),
            JAVA_INT.withName("dwError"),
            JAVA_INT.withName("lChainIndex"),
            JAVA_INT.withName("lElementIndex"),
            ADDRESS.withName("pvExtraPolicyStatus")
    ).withName("CERT_CHAIN_POLICY_STATUS");

    /**
     * Byte offset of a named field, for {@code segment.get(layout, offset(...))}.
     */
    static long offset(MemoryLayout layout, String field) {
        return layout.byteOffset(MemoryLayout.PathElement.groupElement(field));
    }
}
