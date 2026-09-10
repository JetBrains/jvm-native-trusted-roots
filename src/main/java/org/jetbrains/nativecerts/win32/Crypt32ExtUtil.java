package org.jetbrains.nativecerts.win32;

import org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
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

public class Crypt32ExtUtil {
    private static final Logger LOGGER = Logger.getLogger(Crypt32ExtUtil.class.getName());
    private static final Map<String, Integer> customTrustedCertificatesLocations = Map.of(
            "CERT_SYSTEM_STORE_LOCAL_MACHINE", CERT_SYSTEM_STORE_LOCAL_MACHINE,
            "CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY", CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
            "CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE", CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
            "CERT_SYSTEM_STORE_CURRENT_USER", CERT_SYSTEM_STORE_CURRENT_USER,
            "CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY", CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY);

    public static Collection<X509Certificate> getCustomTrustedRootCertificates() {
        var result = new HashSet<X509Certificate>();
        for (var entry : customTrustedCertificatesLocations.entrySet()) {
            var roots = gatherEnterpriseCertsForLocation(entry.getValue(), "ROOT");
            var intermediates = gatherEnterpriseCertsForLocation(entry.getValue(), "CA");
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("Received " + roots.size() + " roots and " + intermediates.size()
                        + " intermediates from " + entry.getKey());
            }
            result.addAll(roots);
            for (var intermediate : intermediates) {
                try {
                    validateCertificate(intermediate.getEncoded());
                    result.add(intermediate);
                } catch (Exception exception) {
                    LOGGER.log(Level.FINE, "Unable to validate certificate '"
                            + intermediate.getSubjectX500Principal() + "'", exception);
                }
            }
        }
        return result;
    }

    public static List<X509Certificate> gatherEnterpriseCertsForLocation(int location, String storeName) {
        try (var arena = Arena.ofConfined()) {
            var state = arena.allocate(CALL_STATE);
            var name = arena.allocateFrom(storeName, StandardCharsets.UTF_16LE);
            int flags = location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG;
            var store = (MemorySegment) OPEN_STORE.invoke(state,
                    MemorySegment.ofAddress(CERT_STORE_PROV_SYSTEM_REGISTRY_W), 0, NULL, flags, name);
            if (store.equals(NULL)) {
                int error = lastError(state);
                if (error == ERROR_NO_MORE_FILES || error == ERROR_FILE_NOT_FOUND) {
                    return List.of();
                }
                throw new WindowsCertificateException(OPEN_STORE.name(), error);
            }

            var certificate = NULL;
            try {
                var result = new ArrayList<X509Certificate>();
                while (true) {
                    var previous = certificate;
                    certificate = NULL;
                    certificate = (MemorySegment) ENUM_CERTIFICATES.invoke(state, store, previous);
                    if (certificate.equals(NULL)) {
                        int error = lastError(state);
                        if (error != CRYPT_E_NOT_FOUND && error != ERROR_NO_MORE_FILES) {
                            throw new WindowsCertificateException(ENUM_CERTIFICATES.name(), error);
                        }
                        break;
                    }
                    var context = certificate.reinterpret(CERT_CONTEXT.byteSize(), arena, null);
                    var data = context.get(ADDRESS, offset(CERT_CONTEXT, "pbCertEncoded"));
                    long length = Integer.toUnsignedLong(context.get(JAVA_INT, offset(CERT_CONTEXT, "cbCertEncoded")));
                    try {
                        var bytes = data.reinterpret(length, arena, null).toArray(JAVA_BYTE);
                        result.add(NativeTrustedRootsInternalUtils.parseCertificate(bytes));
                    } catch (Exception exception) {
                        LOGGER.warning(renderExceptionMessage("Unable to parse a certificate from store '" + storeName + "'", exception));
                    }
                }
                return result;
            } finally {
                try {
                    if (!certificate.equals(NULL)) {
                        FREE_CONTEXT.invoke(certificate);
                    }
                } finally {
                    if ((int) CLOSE_STORE.invoke(state, store, 0) == 0) {
                        throw failure(CLOSE_STORE, state);
                    }
                }
            }
        }
    }

    public static void validateCertificate(byte[] encodedCertificate) {
        try (var arena = Arena.ofConfined()) {
            var state = arena.allocate(CALL_STATE);
            var bytes = arena.allocateFrom(JAVA_BYTE, encodedCertificate);
            var certificate = (MemorySegment) CREATE_CONTEXT.invoke(state,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, bytes, encodedCertificate.length);
            if (certificate.equals(NULL)) {
                throw failure(CREATE_CONTEXT, state);
            }
            try {
                var parameters = arena.allocate(CERT_CHAIN_PARA);
                parameters.set(JAVA_INT, offset(CERT_CHAIN_PARA, "cbSize"), (int) CERT_CHAIN_PARA.byteSize());
                var chainPointer = arena.allocate(ADDRESS);
                if ((int) GET_CHAIN.invoke(state, NULL, certificate, NULL, NULL, parameters,
                        CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, NULL, chainPointer) == 0) {
                    throw failure(GET_CHAIN, state);
                }
                var chain = chainPointer.get(ADDRESS, 0);
                if (chain.equals(NULL)) {
                    throw new IllegalStateException("CertGetCertificateChain returned a null chain");
                }
                try {
                    var policy = arena.allocate(CERT_CHAIN_POLICY_PARA);
                    policy.set(JAVA_INT, offset(CERT_CHAIN_POLICY_PARA, "cbSize"), (int) CERT_CHAIN_POLICY_PARA.byteSize());
                    var status = arena.allocate(CERT_CHAIN_POLICY_STATUS);
                    status.set(JAVA_INT, offset(CERT_CHAIN_POLICY_STATUS, "cbSize"), (int) CERT_CHAIN_POLICY_STATUS.byteSize());
                    status.set(JAVA_INT, offset(CERT_CHAIN_POLICY_STATUS, "dwError"), 1);
                    if ((int) VERIFY_CHAIN_POLICY.invoke(state,
                            MemorySegment.ofAddress(CERT_CHAIN_POLICY_SSL), chain, policy, status) == 0) {
                        throw failure(VERIFY_CHAIN_POLICY, state);
                    }
                    int error = status.get(JAVA_INT, offset(CERT_CHAIN_POLICY_STATUS, "dwError"));
                    if (error != 0) {
                        throw new WindowsCertificateException(VERIFY_CHAIN_POLICY.name(), error);
                    }
                } finally {
                    FREE_CHAIN.invoke(chain);
                }
            } finally {
                FREE_CONTEXT.invoke(certificate);
            }
        }
    }
}
