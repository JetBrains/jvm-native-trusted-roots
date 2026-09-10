package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;
import static org.jetbrains.nativecerts.mac.CoreFoundationExt.*;
import static org.jetbrains.nativecerts.mac.SecurityFramework.*;

public class SecurityFrameworkUtil {
    private static final Logger LOGGER = Logger.getLogger(SecurityFrameworkUtil.class.getName());

    private SecurityFrameworkUtil() {
    }

    public static List<X509Certificate> getTrustedRoots() {
        return getTrustedRoots(false);
    }

    public static List<X509Certificate> getSystemTrustedRoots() {
        return getTrustedRoots(true);
    }

    private static List<X509Certificate> getTrustedRoots(boolean systemDomain) {
        var certificates = getTrustedCertificates(systemDomain);
        if (LOGGER.isLoggable(Level.FINE)) {
            var message = new StringBuilder("Received ").append(certificates.size()).append(" certificates");
            if (systemDomain) {
                message.append(" from the system keychain");
            }
            for (var certificate : certificates) {
                message.append("\n  ").append(certificate.getSubjectX500Principal());
            }
            LOGGER.fine(message.toString());
        }
        return certificates;
    }

    public static List<X509Certificate> getTrustedCertificates(boolean systemDomain) {
        try (var arena = Arena.ofConfined()) {
            var keychainPointer = arena.allocate(ADDRESS);
            var certificatesPointer = arena.allocate(ADDRESS);
            var searchList = NULL;
            var query = NULL;
            try {
                var parameters = new HashMap<MemorySegment, MemorySegment>();
                parameters.put(CLASS, CLASS_CERTIFICATE);
                parameters.put(MATCH_LIMIT, MATCH_LIMIT_ALL);
                parameters.put(RETURN_REF, TRUE);
                if (systemDomain) {
                    var path = arena.allocateFrom("/System/Library/Keychains/SystemRootCertificates.keychain");
                    checkStatus(KEYCHAIN_OPEN.name(), (int) KEYCHAIN_OPEN.invoke(path, keychainPointer));
                    searchList = createArray(requireNonNull(keychainPointer.get(ADDRESS, 0)));
                    parameters.put(MATCH_SEARCH_LIST, searchList);
                }
                query = createDictionary(parameters);
                int status = (int) ITEM_COPY_MATCHING.invoke(query, certificatesPointer);
                if (status == ITEM_NOT_FOUND) {
                    return List.of();
                }
                checkStatus(ITEM_COPY_MATCHING.name(), status);
                var certificates = certificatesPointer.get(ADDRESS, 0);
                if (certificates.equals(NULL)) {
                    return List.of();
                }
                var result = new ArrayList<X509Certificate>();
                long count = arrayCount(certificates);
                for (long index = 0; index < count; index++) {
                    var certificate = arrayValue(certificates, index);
                    try {
                        if (systemDomain || isTrustedRoot(certificate)) {
                            result.add(getX509Certificate(certificate));
                        }
                    } catch (Exception exception) {
                        LOGGER.warning(renderExceptionMessage("Unable to read or check a certificate", exception));
                    }
                }
                return result;
            } finally {
                release(certificatesPointer.get(ADDRESS, 0));
                release(query);
                release(searchList);
                release(keychainPointer.get(ADDRESS, 0));
            }
        }
    }

    private static X509Certificate getX509Certificate(MemorySegment certificate) {
        requireType(certificate, CERTIFICATE_TYPE);
        var data = requireNonNull((MemorySegment) CERTIFICATE_COPY_DATA.invoke(certificate));
        try {
            return NativeTrustedRootsInternalUtils.parseCertificate(dataBytes(data));
        } finally {
            release(data);
        }
    }

    static boolean isSelfSignedCertificate(X509Certificate certificate) {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    @Nullable
    private static CoreFoundationExt.Error validateCertificate(MemorySegment certificate) {
        try (var arena = Arena.ofConfined()) {
            var trustPointer = arena.allocate(ADDRESS);
            var errorPointer = arena.allocate(ADDRESS);
            var subjects = NULL;
            var policy = NULL;
            try {
                subjects = createArray(certificate);
                policy = requireNonNull((MemorySegment) POLICY_CREATE_SSL.invoke((byte) 0, NULL));
                int status = (int) TRUST_CREATE.invoke(subjects, policy, trustPointer);
                if (status != SUCCESS) {
                    return SecurityFramework.error(status);
                }
                var trust = requireNonNull(trustPointer.get(ADDRESS, 0));
                if ((byte) TRUST_EVALUATE.invoke(trust, errorPointer) != 0) {
                    return null;
                }
                var error = errorPointer.get(ADDRESS, 0);
                if (error.equals(NULL)) {
                    throw new IllegalStateException("SecTrustEvaluateWithError failed without an error object");
                }
                return CoreFoundationExt.error(error);
            } finally {
                release(errorPointer.get(ADDRESS, 0));
                release(trustPointer.get(ADDRESS, 0));
                release(policy);
                release(subjects);
            }
        }
    }

    public static boolean isTrustedRoot(MemorySegment certificate) {
        boolean selfSigned = isSelfSignedCertificate(getX509Certificate(certificate));
        var settings = copyTrustSettings(certificate);
        try {
            if (settings.equals(NULL)) {
                var error = validateCertificate(certificate);
                if (error != null) {
                    LOGGER.fine("Certificate '" + description(certificate) + "' has no trust settings and failed validation: " + error);
                }
                return error == null;
            }
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("Certificate '" + description(certificate) + "' trust settings:\n" + description(settings));
            }
            return matchesTrustSettings(settings, selfSigned);
        } finally {
            release(settings);
        }
    }

    static boolean matchesTrustSettings(MemorySegment settings, boolean selfSigned) {
        long count = arrayCount(settings);
        if (count == 0) {
            return true;
        }
        for (long index = 0; index < count; index++) {
            var constraints = arrayValue(settings, index);
            long constraintsCount = dictionaryCount(constraints);
            int processedConstraints = 0;
            var resultValue = dictionaryValue(constraints, TRUST_SETTINGS_RESULT);
            long result = TRUST_ROOT;
            if (!resultValue.equals(NULL)) {
                result = numberValue(resultValue);
                processedConstraints++;
            }
            if (result != TRUST_ROOT || !selfSigned) {
                continue;
            }
            if (!dictionaryValue(constraints, TRUST_SETTINGS_ALLOWED_ERROR).equals(NULL)) {
                processedConstraints++;
            }
            if (!dictionaryValue(constraints, TRUST_SETTINGS_POLICY_NAME).equals(NULL)) {
                processedConstraints++;
            }
            var policy = dictionaryValue(constraints, TRUST_SETTINGS_POLICY);
            if (!policy.equals(NULL)) {
                requireType(policy, POLICY_TYPE);
                var properties = requireNonNull((MemorySegment) POLICY_COPY_PROPERTIES.invoke(policy));
                try {
                    var oid = dictionaryValue(properties, POLICY_OID);
                    if (oid.equals(NULL) || !equal(POLICY_APPLE_SSL, oid)) {
                        continue;
                    }
                } finally {
                    release(properties);
                }
                processedConstraints++;
            }
            if (constraintsCount == processedConstraints) {
                return true;
            }
        }
        return false;
    }

    private static MemorySegment copyTrustSettings(MemorySegment certificate) {
        var settings = copyTrustSettings(certificate, USER);
        return settings.equals(NULL) ? copyTrustSettings(certificate, ADMIN) : settings;
    }

    private static MemorySegment copyTrustSettings(MemorySegment certificate, int domain) {
        try (var arena = Arena.ofConfined()) {
            var settings = arena.allocate(ADDRESS);
            int status = (int) COPY_TRUST_SETTINGS.invoke(certificate, domain, settings);
            if (status == ITEM_NOT_FOUND) {
                return NULL;
            }
            checkStatus(COPY_TRUST_SETTINGS.name(), status);
            return settings.get(ADDRESS, 0);
        }
    }
}
