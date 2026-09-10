package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;
import static org.jetbrains.nativecerts.mac.CoreFoundationExtUtil.*;
import static org.jetbrains.nativecerts.mac.SecurityFramework.*;

/**
 * Get trusted certificates stored in corresponding keychains via Security frameworks APIs.
 * for the other implementations, see root_cgo_darwin.go in Go and trust_store_mac.cc in Chromium
 * <br><br>
 * In the future it would be better to implement {@code X509TrustManager} on <a href="https://developer.apple.com/documentation/security/2980705-sectrustevaluatewitherror">SecTrustEvaluateWithError</a> instead
 * of getting the trust chain manually. It's not yet investigated whether it is possible at all to integrate it into
 * the SSL framework of JVM.
 * <br><br>
 * Native objects are opaque pointers ({@link MemorySegment}); see {@link SecurityFramework} and
 * {@link CoreFoundationExt} for the bindings and {@link CoreFoundationExtUtil} for type-checked accessors.
 */
public class SecurityFrameworkUtil {
    private final static Logger LOGGER = Logger.getLogger(SecurityFrameworkUtil.class.getName());

    private SecurityFrameworkUtil() {
    }

    /**
     * Get trusted roots installed on admin and user level (domain)
     */
    public static List<X509Certificate> getTrustedRoots() {
        return getTrustedRoots(/* systemDomain*/ false);
    }

    /**
     * Get trusted roots backed into macOS (system domain)
     */
    public static List<X509Certificate> getSystemTrustedRoots() {
        return getTrustedRoots(/* systemDomain*/ true);
    }

    private static List<X509Certificate> getTrustedRoots(boolean systemDomain) {
        List<X509Certificate> result = getTrustedCertificates(systemDomain);

        if (LOGGER.isLoggable(Level.FINE)) {
            StringBuilder message = new StringBuilder();
            message.append("Received ").append(result.size()).append(" certificates");

            if (systemDomain) {
                message.append(" from the system keychain");
            }

            for (X509Certificate certificate : result) {
                message.append("\n  ").append(certificate.getSubjectX500Principal());
            }

            LOGGER.fine(message.toString());
        }

        return result;
    }

    /**
     * Enumerates certificates via {@code SecItemCopyMatching}.
     *
     * @param systemDomain true: certificates from the immutable system roots keychain (all implicitly trusted);
     *                     false: certificates from the default keychain search list (login + System keychains),
     *                     filtered by {@link #isTrustedRoot}
     */
    @NotNull
    public static List<X509Certificate> getTrustedCertificates(boolean systemDomain) {
        try (Arena arena = Arena.ofConfined()) {
            // out-parameters: SecKeychainRef* and CFArrayRef*
            MemorySegment keychainRef = arena.allocate(ADDRESS);
            MemorySegment returnedCertArrayRef = arena.allocate(ADDRESS);

            MemorySegment searchDomainList = NULL;
            MemorySegment query = NULL;
            try {
                Map<MemorySegment, MemorySegment> map = new HashMap<>();

                map.put(kSecClass, kSecClassCertificate);
                map.put(kSecMatchLimit, kSecMatchLimitAll);
                map.put(kSecReturnRef, CoreFoundationExt.kCFBooleanTrue);

                if (systemDomain) {
                    // `SecKeychainCopyDomainSearchList` doesn't return the keychain for the system domain,
                    // so open the system roots keychain by its well-known path and search only in it
                    MemorySegment path = arena.allocateFrom("/System/Library/Keychains/SystemRootCertificates.keychain");
                    int rc = SecKeychainOpen(path, keychainRef);
                    if (rc != errSecSuccess) {
                        throw new IllegalStateException("Failed to read system keychain: " + toError(rc));
                    }

                    searchDomainList = createArray(requireNonNull(keychainRef.get(ADDRESS, 0)));
                    map.put(kSecMatchSearchList, searchDomainList);
                }

                query = createDictionary(map);

                int rc = SecItemCopyMatching(query, returnedCertArrayRef);
                if (rc == errSecItemNotFound) {
                    // no certificates at all in the searched keychains
                    return Collections.emptyList();
                }
                if (rc != errSecSuccess) {
                    throw new IllegalStateException("SecItemCopyMatching failed: " + toError(rc));
                }

                MemorySegment certArray = returnedCertArrayRef.get(ADDRESS, 0);
                if (certArray.equals(NULL)) {
                    return Collections.emptyList();
                }

                List<X509Certificate> result = new ArrayList<>();

                long count = getArrayCount(certArray);
                for (long i = 0; i < count; i++) {
                    // borrowed reference, owned by certArray
                    MemorySegment secCertificateRef = getValueAtIndex(certArray, i);
                    requireType(secCertificateRef, SEC_CERTIFICATE_TYPE_ID);

                    // system domain certificates are implicitly trusted
                    if (!systemDomain) {
                        try {
                            boolean trustedRoot = isTrustedRoot(secCertificateRef);
                            if (!trustedRoot) {
                                String certificateDescription = getDescription(secCertificateRef);
                                LOGGER.fine("Certificate '" + certificateDescription + "' has failed to validate against trusted roots");
                                continue;
                            }
                        } catch (Throwable validateException) {
                            String certificateDescription = getDescription(secCertificateRef);
                            LOGGER.warning(renderExceptionMessage("Unable to check certificate '" + certificateDescription + "'", validateException));
                            continue;
                        }
                    }

                    try {
                        result.add(getX509Certificate(secCertificateRef));
                    } catch (Throwable parsingError) {
                        String certificateDescription = getDescription(secCertificateRef);
                        LOGGER.warning(renderExceptionMessage("Unable to parse certificate '" + certificateDescription + "'", parsingError));
                    }
                }

                return result;
            } finally {
                release(query);
                release(returnedCertArrayRef.get(ADDRESS, 0));
                release(searchDomainList);
                release(keychainRef.get(ADDRESS, 0));
            }
        }
    }

    /**
     * DER bytes of a SecCertificateRef parsed into a Java certificate.
     */
    private static X509Certificate getX509Certificate(@NotNull MemorySegment secCertificateRef) {
        requireType(secCertificateRef, SEC_CERTIFICATE_TYPE_ID);
        MemorySegment data = requireNonNull(SecCertificateCopyData(secCertificateRef));
        try {
            return NativeTrustedRootsInternalUtils.parseCertificate(getBytes(data));
        } catch (Exception e) {
            throw new RuntimeException(e);
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
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    /**
     * Asks the Security framework whether the certificate is trusted for SSL.
     *
     * @return null if the certificate is trusted, the evaluation error otherwise
     */
    @Nullable
    private static CoreFoundationExt.Error validateCertificate(@NotNull MemorySegment certificateRef) {
        try (Arena arena = Arena.ofConfined()) {
            // out-parameters: SecTrustRef* and CFErrorRef*
            MemorySegment secTrustRef = arena.allocate(ADDRESS);
            MemorySegment errorRef = arena.allocate(ADDRESS);

            MemorySegment policy = NULL;
            MemorySegment subjCerts = NULL;
            try {
                subjCerts = createArray(certificateRef);

                // Why server == false?
                // When server == true, Apple stack enable more strict processing of certificates
                // See
                //   https://discussions.apple.com/thread/254684451
                //   https://discussions.apple.com/thread/254960840
                //   https://www.michalspacek.com/validity-period-of-https-certificates-issued-from-a-user-added-ca-is-essentially-2-years
                // This leads to returning some non-server certificates as trusted,
                // but the real TLS stack will check basicConstraints/extendedKeyUsage anyway.
                policy = requireNonNull(SecPolicyCreateSSL(/* server */ false, /* hostname */ null));

                int rc = SecTrustCreateWithCertificates(subjCerts, policy, secTrustRef);
                if (rc != errSecSuccess) {
                    CoreFoundationExt.Error error = toError(rc);
                    LOGGER.warning("Failed to create trust object: " + error);
                    return error;
                }

                boolean trusted = SecTrustEvaluateWithError(requireNonNull(secTrustRef.get(ADDRESS, 0)), errorRef);
                if (trusted) {
                    return null;
                }

                MemorySegment error = errorRef.get(ADDRESS, 0);
                if (error.equals(NULL)) {
                    throw new IllegalStateException("SecTrustEvaluateWithError returned false without an error object");
                }
                return CoreFoundationExtUtil.toError(error);
            } finally {
                release(errorRef.get(ADDRESS, 0));
                release(secTrustRef.get(ADDRESS, 0));
                release(policy);
                release(subjCerts);
            }
        }
    }

    /**
     * Decides whether a certificate from the user/admin keychains is a trusted root for our purposes:
     * either it has explicit trust settings that we understand and that say "trust as root for SSL",
     * or it has no trust settings and the Security framework validates it against the trusted roots.
     *
     * @param certificateRef SecCertificateRef (borrowed)
     */
    public static boolean isTrustedRoot(@NotNull MemorySegment certificateRef) {
        boolean selfSignedCertificate = isSelfSignedCertificate(getX509Certificate(certificateRef));

        MemorySegment trustedSettingsArray = copyTrustSettings(certificateRef);
        try {
            String certificateDescription = getDescription(certificateRef);

            if (trustedSettingsArray.equals(NULL)) {
                // Trust record is null we need to verify the certificate first
                CoreFoundationExt.Error error = validateCertificate(certificateRef);
                if (error == null) {
                    return true;
                } else {
                    LOGGER.fine("Certificate '" + certificateDescription + "' has no trust settings and failed to validate against trusted roots: " + error);
                    return false;
                }
            }

            if (LOGGER.isLoggable(Level.FINE)) {
                try {
                    String description = getDescription(trustedSettingsArray);
                    LOGGER.fine("Certificate '" + certificateDescription + "' trust settings:\n" + description);
                } catch (Throwable t) {
                    LOGGER.warning(renderExceptionMessage("Unable to describe certificate trusted settings", t));
                }
            }

            return matchesTrustSettings(trustedSettingsArray, selfSignedCertificate, certificateDescription);
        } finally {
            release(trustedSettingsArray);
        }
    }

    static boolean matchesTrustSettings(@NotNull MemorySegment trustedSettingsArray, boolean selfSignedCertificate) {
        return matchesTrustSettings(trustedSettingsArray, selfSignedCertificate, "<unknown>");
    }

    /**
     * Interprets the array of usage constraints dictionaries returned by {@code SecTrustSettingsCopyTrustSettings}.
     *
     * @param trustedSettingsArray CFArrayRef of CFDictionaryRef, see {@code kSecTrustSettings*} keys in {@link SecurityFramework}
     * @return true if at least one usage constraints dictionary says "trust as root for SSL" and consists only
     * of constraints we know how to evaluate
     */
    static boolean matchesTrustSettings(@NotNull MemorySegment trustedSettingsArray, boolean selfSignedCertificate, @NotNull String certificateDescription) {
        long settingsCount = getArrayCount(trustedSettingsArray);
        if (settingsCount == 0) {
            // https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting
            // An empty trust settings array (that is, the trustSettings parameter returns a valid but empty CFArray) means "always trust this certificate" with an overall trust setting for the certificate of kSecTrustSettingsResultTrustRoot
            return true;
        }

        for (long i = 0; i < settingsCount; i++) {
            MemorySegment constraints = getValueAtIndex(trustedSettingsArray, i);
            long constraintsCount = getDictionaryCount(constraints);
            int processedConstrains = 0;

            // kSecTrustSettingsResult
            {
                MemorySegment value = getValue(constraints, kSecTrustSettingsResult);

                // from https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting
                // If this key is not present, a default value of kSecTrustSettingsResultTrustRoot is assumed. Because only a root certificate can have this value, a usage constraints dictionary for a non-root certificate that is missing this key is not valid.
                // Note the distinction between the results kSecTrustSettingsResultTrustRoot and kSecTrustSettingsResultTrustAsRoot: The former can only be applied to a root (self-signed) certificates; the latter can only be applied to non-root certificates. Therefore, an empty trust settings array for a non-root certificate is invalid, because the default value of kSecTrustSettingsResultTrustRoot is not valid for a non-root certificate.

                long result;
                if (value.equals(NULL)) {
                    result = kSecTrustSettingsResultTrustRoot;
                } else {
                    result = longValue(value);
                    processedConstrains++;
                }

                // Return only trust roots. Skip even kSecTrustSettingsResultTrustAsRoot for now
                if (result != kSecTrustSettingsResultTrustRoot) {
                    continue;
                }

                // trust roots must be self-signed, see above
                if (!selfSignedCertificate) {
                    LOGGER.warning("Certificate '" + certificateDescription + "' is not self-signed, skipping");
                    continue;
                }
            }

            // kSecTrustSettingsAllowedError
            {
                // Skip kSecTrustSettingsAllowedError processing
                // Documentation says "A number which, if encountered during certificate verification, is ignored for that certificate."
                // We would not ignore anything, so skip for now
                if (!getValue(constraints, kSecTrustSettingsAllowedError).equals(NULL)) {
                    processedConstrains++;
                }
            }

            // kSecTrustSettingsPolicyName
            {
                // Skip kSecTrustSettingsPolicyName, it does not matter for processing
                if (!getValue(constraints, kSecTrustSettingsPolicyName).equals(NULL)) {
                    processedConstrains++;
                }
            }

            // kSecTrustSettingsPolicy
            {
                MemorySegment secPolicyRef = getValue(constraints, kSecTrustSettingsPolicy);
                if (!secPolicyRef.equals(NULL)) {
                    requireType(secPolicyRef, SEC_POLICY_TYPE_ID);

                    MemorySegment policyDictionaryRef = requireNonNull(SecPolicyCopyProperties(secPolicyRef));
                    try {
                        MemorySegment policyOid = getValue(policyDictionaryRef, kSecPolicyOid);
                        if (policyOid.equals(NULL)) {
                            // Must be present, so it's an invalid policy
                            continue;
                        }

                        if (!equal(kSecPolicyAppleSSL, policyOid)) {
                            // Accept only kSecPolicyAppleSSL policy
                            continue;
                        }
                    } finally {
                        release(policyDictionaryRef);
                    }

                    processedConstrains++;
                }
            }

            if (constraintsCount == processedConstrains) {
                // return only certificates with known and checked constraints attached to them
                // this way we'll probably miss some valid trusted roots, but
                // there is no way to evaluate other and possibly unknown constraints
                return true;
            }
        }

        // No matched constraints => not a trusted root
        return false;
    }

    /**
     * Trust settings from the user domain, falling back to the admin domain.
     *
     * @return CFArrayRef owned by the caller, or NULL if the certificate has no trust settings in either domain
     */
    @NotNull
    private static MemorySegment copyTrustSettings(@NotNull MemorySegment certificateRef) {
        MemorySegment trustedSettings = copyTrustSettings(certificateRef, kSecTrustSettingsDomainUser);
        if (trustedSettings.equals(NULL)) {
            trustedSettings = copyTrustSettings(certificateRef, kSecTrustSettingsDomainAdmin);
        }

        return trustedSettings;
    }

    @NotNull
    private static MemorySegment copyTrustSettings(@NotNull MemorySegment certificateRef, int domain) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment trustedSettingsRef = arena.allocate(ADDRESS);

            int rc = SecTrustSettingsCopyTrustSettings(certificateRef, domain, trustedSettingsRef);

            if (rc == errSecItemNotFound) {
                return NULL;
            }

            if (rc != errSecSuccess) {
                String certificateDescription = getDescription(certificateRef);
                throw new IllegalStateException("Failed to get trust settings for certificate '" +
                        certificateDescription + "': " + toError(rc));
            }

            return trustedSettingsRef.get(ADDRESS, 0);
        }
    }
}
