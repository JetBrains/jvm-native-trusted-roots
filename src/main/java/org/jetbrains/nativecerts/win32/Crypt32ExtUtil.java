package org.jetbrains.nativecerts.win32;

import org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;
import static org.jetbrains.nativecerts.win32.Crypt32Ext.*;
import static org.jetbrains.nativecerts.win32.WinCryptStructures.*;

/**
 * Get custom (enterprise/user-installed) trusted root certificates from Windows certificate stores via CryptoAPI.
 * <br><br>
 * Native handles and structures are opaque {@link MemorySegment}s; see {@link Crypt32Ext} for the bindings
 * and {@link WinCryptStructures} for the structure layouts.
 */
public class Crypt32ExtUtil {
    private final static Logger LOGGER = Logger.getLogger(Crypt32ExtUtil.class.getName());

    /**
     * Physical store locations that may contain certificates added by the user or by an administrator/group policy,
     * as opposed to the Windows-supplied roots (which the JVM already trusts via its own cacerts/Windows-ROOT store).
     */
    private static final Map<String, Integer> customTrustedCertificatesLocations = Map.of(
            "CERT_SYSTEM_STORE_LOCAL_MACHINE", CERT_SYSTEM_STORE_LOCAL_MACHINE,
            "CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY", CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
            "CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE", CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
            "CERT_SYSTEM_STORE_CURRENT_USER", CERT_SYSTEM_STORE_CURRENT_USER,
            "CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY", CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY
    );

    /**
     * Certificates from the "ROOT" stores of all {@link #customTrustedCertificatesLocations} plus those intermediate
     * ("CA" store) certificates that Windows itself can validate up to a trusted root.
     */
    public static Collection<X509Certificate> getCustomTrustedRootCertificates() {
        HashSet<X509Certificate> result = new HashSet<>();

        for (Map.Entry<String, Integer> entry : customTrustedCertificatesLocations.entrySet()) {
            List<X509Certificate> root = gatherEnterpriseCertsForLocation(entry.getValue(), "ROOT");
            List<X509Certificate> intermediates = gatherEnterpriseCertsForLocation(entry.getValue(), "CA");

            if (LOGGER.isLoggable(Level.FINE)) {
                StringBuilder message = new StringBuilder();

                message.append("Received ").append(root.size()).append(" certificates from store ROOT / ").append(entry.getKey());
                for (X509Certificate certificate : root) {
                    message.append("\n  ROOT/").append(entry.getKey()).append(": ").append(certificate.getSubjectX500Principal());
                }

                message.append("\nReceived ").append(intermediates.size()).append(" certificates from store CA (Intermediates) / ").append(entry.getKey());
                for (X509Certificate certificate : intermediates) {
                    message.append("\n  CA/").append(entry.getKey()).append(": ").append(certificate.getSubjectX500Principal());
                }

                LOGGER.fine(message.toString());
            }

            result.addAll(root);

            for (X509Certificate intermediate : intermediates) {
                try {
                    validateCertificate(intermediate.getEncoded());
                    result.add(intermediate);
                } catch (Throwable t) {
                    LOGGER.log(
                            Level.FINE,
                            "Unable to validate whether certificate '" + intermediate.getSubjectX500Principal() + "' is trusted: " + t.getMessage(),
                            t);
                }
            }
        }

        return result;
    }

    /**
     * Enumerates all certificates of one physical system store.
     *
     * @param location  One of {@code CERT_SYSTEM_STORE_*} constants
     * @param storeName Logical store name, e.g. "ROOT" or "CA"
     * @return Parsed certificates; an empty list if the store does not exist
     */
    public static List<X509Certificate> gatherEnterpriseCertsForLocation(int location, String storeName) {
        int flags = location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment callState = arena.allocate(CALL_STATE_LAYOUT);

            MemorySegment hCertStore = CertOpenStore(
                    callState,
                    /* lpszStoreProvider */ MemorySegment.ofAddress(CERT_STORE_PROV_SYSTEM_REGISTRY_W),
                    /* dwEncodingType */ 0,
                    /* hCryptProv */ null,
                    flags,
                    /* pvPara */ arena.allocateFrom(storeName, StandardCharsets.UTF_16LE));
            if (hCertStore.equals(NULL)) {
                int errorCode = getLastError(callState);

                if (errorCode == ERROR_NO_MORE_FILES || errorCode == ERROR_FILE_NOT_FOUND) {
                    return Collections.emptyList();
                } else {
                    throw new WindowsCertificateException("CertOpenStore", errorCode);
                }
            }

            // the context currently owned by us; CertEnumCertificatesInStore frees the previous one on each call,
            // so only the last returned one has to be freed explicitly if we bail out of the loop early
            MemorySegment certificate = NULL;
            try {
                List<X509Certificate> result = new ArrayList<>();

                while (true) {
                    MemorySegment prev = certificate;
                    certificate = NULL; // prev is freed by the call below even if it fails
                    certificate = CertEnumCertificatesInStore(callState, hCertStore, prev.equals(NULL) ? null : prev);
                    if (certificate.equals(NULL)) {
                        int errorCode = getLastError(callState);
                        if (errorCode != CRYPT_E_NOT_FOUND && errorCode != ERROR_NO_MORE_FILES) {
                            throw new WindowsCertificateException("CertEnumCertificatesInStore", errorCode);
                        }

                        break;
                    }

                    // read CERT_CONTEXT.pbCertEncoded / cbCertEncoded
                    MemorySegment certContext = certificate.reinterpret(CERT_CONTEXT.byteSize(), arena, null);
                    MemorySegment pbCertEncoded = certContext.get(ADDRESS, offset(CERT_CONTEXT, "pbCertEncoded"));
                    long cbCertEncoded = Integer.toUnsignedLong(certContext.get(JAVA_INT, offset(CERT_CONTEXT, "cbCertEncoded")));

                    try {
                        byte[] bytes = pbCertEncoded.reinterpret(cbCertEncoded, arena, null).toArray(JAVA_BYTE);
                        X509Certificate x509 = NativeTrustedRootsInternalUtils.parseCertificate(bytes);
                        result.add(x509);
                    } catch (Throwable parsingException) {
                        LOGGER.warning(renderExceptionMessage(
                                "Unable to parse one of the certificates" +
                                        "from store '" + storeName + "'",
                                parsingException));
                    }
                }

                return result;
            } finally {
                try {
                    if (!certificate.equals(NULL)) {
                        CertFreeCertificateContext(certificate);
                    }
                } finally {
                    if (!CertCloseStore(callState, hCertStore, 0)) {
                        throw new WindowsCertificateException("CertCloseStore", getLastError(callState));
                    }
                }
            }
        }
    }

    /**
     * Asks Windows to build a certificate chain for the given certificate (offline, using cached revocation data only)
     * and to verify it against the SSL policy.
     *
     * @throws WindowsCertificateException if the chain cannot be built or does not satisfy the policy,
     *                                     e.g. with {@link Crypt32Ext#CERT_E_UNTRUSTEDROOT} when the root is not trusted
     */
    public static void validateCertificate(byte[] encodedCertificate) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment callState = arena.allocate(CALL_STATE_LAYOUT);

            MemorySegment certificateContext = CertCreateCertificateContext(
                    callState,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    arena.allocateFrom(JAVA_BYTE, encodedCertificate),
                    encodedCertificate.length);
            if (certificateContext.equals(NULL)) {
                throw new WindowsCertificateException("CertCreateCertificateContext", getLastError(callState));
            }

            try {
                // CERT_CHAIN_PARA: match any usage (cUsageIdentifier = 0, rgpszUsageIdentifier = NULL)
                MemorySegment pChainPara = arena.allocate(CERT_CHAIN_PARA); // zero-initialized
                pChainPara.set(JAVA_INT, offset(CERT_CHAIN_PARA, "cbSize"), (int) CERT_CHAIN_PARA.byteSize());
                MemorySegment requestedUsage = pChainPara.asSlice(offset(CERT_CHAIN_PARA, "RequestedUsage"), CERT_USAGE_MATCH);
                requestedUsage.set(JAVA_INT, offset(CERT_USAGE_MATCH, "dwType"), USAGE_MATCH_TYPE_AND);

                MemorySegment ppChainContext = arena.allocate(ADDRESS);
                if (!CertGetCertificateChain(
                        callState,
                        /* hChainEngine */ null,
                        certificateContext,
                        /* pTime */ null,
                        /* hAdditionalStore */ null,
                        pChainPara,
                        CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
                        /* pvReserved */ null,
                        ppChainContext)) {
                    throw new WindowsCertificateException("CertGetCertificateChain", getLastError(callState));
                }

                MemorySegment pChainContext = ppChainContext.get(ADDRESS, 0);
                if (pChainContext.equals(NULL)) {
                    throw new IllegalStateException("CertGetCertificateChain was successful, but returned chain context is null");
                }

                try {
                    int cbSize = pChainContext.reinterpret(CERT_CHAIN_CONTEXT.byteSize(), arena, null)
                            .get(JAVA_INT, offset(CERT_CHAIN_CONTEXT, "cbSize"));
                    if (cbSize != CERT_CHAIN_CONTEXT.byteSize()) {
                        throw new IllegalStateException("CertGetCertificateChain was successful, but returned chain context size is incorrect." +
                                "returned cbSize is " + cbSize + ", but the structure size is " + CERT_CHAIN_CONTEXT.byteSize());
                    }

                    MemorySegment chainPolicyPara = arena.allocate(CERT_CHAIN_POLICY_PARA); // zero-initialized
                    chainPolicyPara.set(JAVA_INT, offset(CERT_CHAIN_POLICY_PARA, "cbSize"), (int) CERT_CHAIN_POLICY_PARA.byteSize());
                    chainPolicyPara.set(JAVA_INT, offset(CERT_CHAIN_POLICY_PARA, "dwFlags"), 0);

                    MemorySegment policyStatus = arena.allocate(CERT_CHAIN_POLICY_STATUS); // zero-initialized
                    policyStatus.set(JAVA_INT, offset(CERT_CHAIN_POLICY_STATUS, "cbSize"), (int) CERT_CHAIN_POLICY_STATUS.byteSize());
                    // extra check that CertVerifyCertificateChainPolicy actually sets this field
                    policyStatus.set(JAVA_INT, offset(CERT_CHAIN_POLICY_STATUS, "dwError"), 1);

                    if (!CertVerifyCertificateChainPolicy(
                            callState,
                            /* pszPolicyOID */ MemorySegment.ofAddress(CERT_CHAIN_POLICY_SSL),
                            pChainContext,
                            chainPolicyPara,
                            policyStatus)) {
                        throw new WindowsCertificateException("CertVerifyCertificateChainPolicy", getLastError(callState));
                    }

                    int dwError = policyStatus.get(JAVA_INT, offset(CERT_CHAIN_POLICY_STATUS, "dwError"));
                    if (dwError != 0) {
                        throw new WindowsCertificateException("CertVerifyCertificateChainPolicy: certificate validation", dwError);
                    }
                } finally {
                    CertFreeCertificateChain(pChainContext);
                }
            } finally {
                CertFreeCertificateContext(certificateContext);
            }
        }
    }
}
