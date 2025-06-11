package org.jetbrains.nativecerts.mac;

import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils;
import org.jetbrains.nativecerts.mac.CoreFoundationExt.CFArrayRefByReference;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;

/**
 * Get trusted certificates stored in corresponding keychains via Security frameworks APIs.
 * for the other implementations, see root_cgo_darwin.go in Go and trust_store_mac.cc in Chromium
 * <br><br>
 * In the future it would be better to implement {@code X509TrustManager} on <a href="https://developer.apple.com/documentation/security/2980705-sectrustevaluatewitherror">SecTrustEvaluateWithError</a> instead
 * of getting the trust chain manually. It's not yet investigated whether it is possible at all to integrate it into
 * the SSL framework of JVM.
 */
public class SecurityFrameworkUtil {
    private final static Logger LOGGER = Logger.getLogger(SecurityFrameworkUtil.class.getName());

    public static final String SERVER_POLICY_PROPERTY = "org.jetbrains.nativecerts.mac.server_policy";
    /**
     * "server" policy should be used for evaluating certificates, but previously it was not.
     * This option is to retain compatibility.
     */
    private final static boolean ourIsServerPolicy = Boolean.parseBoolean(System.getProperty(SERVER_POLICY_PROPERTY, "true"));

    private SecurityFrameworkUtil() {
    }

    final static String SECURITY_FRAMEWORK_LIBRARY_NAME = "Security";

    public static List<X509Certificate> getTrustedRoots(SecurityFramework.SecTrustSettingsDomain domain) {
        List<X509Certificate> result = copyMatchingCertificates(domain, cert -> isTrustedRoot(domain, cert));

        if (LOGGER.isLoggable(Level.FINE)) {
            StringBuilder message = new StringBuilder();
            message.append("Received ").append(result.size()).append(" certificates from trust settings domain ").append(domain);

            for (X509Certificate certificate : result) {
                message.append("\n  ").append(certificate.getSubjectX500Principal());
            }

            LOGGER.fine(message.toString());
        }

        return result;
    }

    @NotNull
    public static List<X509Certificate> copyMatchingCertificates(
            SecurityFramework.SecTrustSettingsDomain domain,
            Predicate<SecurityFramework.SecCertificateRef> predicate
    ) {
        CFArrayRefByReference returnedCertArray = new CFArrayRefByReference();
        CFArrayRefByReference searchDomainArray = new CFArrayRefByReference();
        SecurityFramework.SecKeychainRefByReference keychain = new SecurityFramework.SecKeychainRefByReference();
        CoreFoundation.CFArrayRef searchDomainList = null;
        CoreFoundation.CFArrayRef certArray = null;

        boolean systemDomain = domain.equals(SecurityFramework.SecTrustSettingsDomain.system);
        CoreFoundation.CFDictionaryRef query = null;
        try {
            if (systemDomain) {
                // `SecKeychainCopyDomainSearchList` doesn't return the keychain for the system domain
                SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", keychain);
                if (!SecurityFramework.OSStatus.errSecSuccess.equals(rc)) {
                    throw new IllegalStateException("Failed to read system keychain: " + rc);
                }

                searchDomainList = CoreFoundation.INSTANCE.CFArrayCreate(
                        null, keychain.getPointer(), new CoreFoundation.CFIndex(1), null
                );
            } else {
                SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecKeychainCopyDomainSearchList(domain, searchDomainArray);
                if (!SecurityFramework.OSStatus.errSecSuccess.equals(rc)) {
                    throw new IllegalStateException("SecKeychainCopyDomainSearchList failed: " + rc);
                }
                searchDomainList = searchDomainArray.getArray();
            }
            if (searchDomainList == null) {
                throw new IllegalStateException("Unexpected null search domain list");
            }
            query = CoreFoundationExtUtil.createDictionary(
                    Map.of(
                            SecurityFramework.kSecClass, SecurityFramework.kSecClassCertificate,
                            SecurityFramework.kSecMatchLimit, SecurityFramework.kSecMatchLimitAll,
                            SecurityFramework.kSecReturnRef, CoreFoundationExt.kCFBooleanTrue,
                            SecurityFramework.kSecMatchSearchList, searchDomainList
                    )
            );

            SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecItemCopyMatching(query, returnedCertArray);

            if (!SecurityFramework.OSStatus.errSecSuccess.equals(rc)) {
                throw new IllegalStateException("SecItemCopyMatching failed: " + rc);
            }

            certArray = returnedCertArray.getArray();
            if (certArray == null) {
                return Collections.emptyList();
            }

            List<X509Certificate> result = new ArrayList<>();

            for (int i = 0; i < certArray.getCount(); i++) {
                SecurityFramework.SecCertificateRef secCertificateRef = new SecurityFramework.SecCertificateRef(certArray.getValueAtIndex(i));
                if (!systemDomain) {
                    try {
                        if (!predicate.test(secCertificateRef)) {
                            continue;
                        }
                    } catch (Throwable predicateError) {
                        String certificateDescription = CoreFoundationExtUtil.getDescription(secCertificateRef);
                        LOGGER.warning(renderExceptionMessage("Unable to check certificate '" + certificateDescription + "'", predicateError));
                        continue;
                    }
                }

                try {
                    result.add(getX509Certificate(secCertificateRef));
                } catch (Throwable parsingError) {
                    String certificateDescription = CoreFoundationExtUtil.getDescription(secCertificateRef);
                    LOGGER.warning(renderExceptionMessage("Unable to parse certificate '" + certificateDescription + "'", parsingError));
                }
            }

            return result;
        } finally {
            if (query != null) {
                query.release();
            }
            if (certArray != null) {
                certArray.release();
            }
            if (searchDomainList != null) {
                searchDomainList.release();
            }
            SecurityFramework.SecKeychainRef secKeychainRef = keychain.getSecKeychainRef();
            if (secKeychainRef != null) {
                secKeychainRef.release();
            }
        }
    }

    private static X509Certificate getX509Certificate(SecurityFramework.SecCertificateRef secCertificateRef) {
        CoreFoundation.CFDataRef data = SecurityFramework.INSTANCE.SecCertificateCopyData(secCertificateRef);
        try {
            byte[] bytes = data.getBytePtr().getByteArray(0, data.getLength());
            return NativeTrustedRootsInternalUtils.parseCertificate(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            data.release();
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

    @Nullable
    private static CoreFoundationExt.Error validateCertificate(SecurityFramework.SecCertificateRef certificateRef) {
        SecurityFramework.SecPolicyRef policy = null;
        SecurityFramework.SecTrustRefByReference secTrustRefByReference = null;
        CoreFoundation.CFArrayRef subjCerts = null;
        try {
            subjCerts = CoreFoundationExtUtil.createArray(new CoreFoundation.CFTypeRef[]{certificateRef});

            secTrustRefByReference = new SecurityFramework.SecTrustRefByReference();

            if (!ourIsServerPolicy) {
                LOGGER.warning(
                        "Using 'client' policy for certificate validation, this is not recommended. " +
                        "Drop setting of '" + SERVER_POLICY_PROPERTY + "' property from JVM options to use 'server' policy by default.");
            }

            policy = SecurityFramework.INSTANCE.SecPolicyCreateSSL(ourIsServerPolicy, null);
            SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecTrustCreateWithCertificates(
                    subjCerts, policy, secTrustRefByReference);
            if (!SecurityFramework.OSStatus.errSecSuccess.equals(rc)) {
                String description = "Failed to create trust object: " + rc;
                LOGGER.warning(description);
                return rc.toError();
            }

            CoreFoundationExt.CFErrorRef.ByReference errorRef = new CoreFoundationExt.CFErrorRef.ByReference();
            boolean trusted = SecurityFramework.INSTANCE.SecTrustEvaluateWithError(secTrustRefByReference.getSecTrustRef(), errorRef);
            if (!trusted) {
                CoreFoundationExt.CFErrorRef error = errorRef.getErrorRefValue();
                return error.toError();
            }

            return null;
        } finally {
            if (policy != null) {
                policy.release();
            }
            if (secTrustRefByReference != null) {
                SecurityFramework.SecTrustRef secTrustRef = secTrustRefByReference.getSecTrustRef();
                if (secTrustRef != null) {
                    secTrustRef.release();
                }
            }
            if (subjCerts != null) {
                subjCerts.release();
            }
        }
    }

    public static boolean isTrustedRoot(SecurityFramework.SecTrustSettingsDomain domain, SecurityFramework.SecCertificateRef certificateRef) {
        boolean selfSignedCertificate = isSelfSignedCertificate(getX509Certificate(certificateRef));
        CFArrayRefByReference trustedSettingsRef = new CFArrayRefByReference();

        try {
            SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecTrustSettingsCopyTrustSettings(certificateRef, domain, trustedSettingsRef);

            String certificateDescription = CoreFoundationExtUtil.getDescription(certificateRef);

            CoreFoundation.CFArrayRef trustedSettingsArray = trustedSettingsRef.getArray();
            if (!SecurityFramework.OSStatus.errSecSuccess.equals(rc) && !SecurityFramework.OSStatus.errSecItemNotFound.equals(rc)) {
                LOGGER.fine("Failed to get trust settings for certificate '" + certificateDescription + "': " + rc);
                return false;
            }

            if (trustedSettingsArray == null) {
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
                    String description = CoreFoundationExtUtil.getDescription(trustedSettingsArray);
                    LOGGER.fine("Certificate '" + certificateDescription + "' trust settings:\n" + description);
                } catch (Throwable t) {
                    LOGGER.warning(renderExceptionMessage("Unable to describe certificate trusted settings", t));
                }
            }

            if (trustedSettingsArray.getCount() == 0) {
                // https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting
                // An empty trust settings array (that is, the trustSettings parameter returns a valid but empty CFArray) means "always trust this certificate" with an overall trust setting for the certificate of kSecTrustSettingsResultTrustRoot
                return true;
            }

            for (int i = 0; i < trustedSettingsArray.getCount(); i++) {
                CoreFoundation.CFDictionaryRef constraints = new CoreFoundation.CFDictionaryRef(trustedSettingsArray.getValueAtIndex(i));
                CoreFoundation.CFIndex constraintsCount = CoreFoundationExt.INSTANCE.CFDictionaryGetCount(constraints);
                int processedConstrains = 0;

                // kSecTrustSettingsResult
                {
                    Pointer value = constraints.getValue(SecurityFramework.kSecTrustSettingsResult);

                    // from https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting
                    // If this key is not present, a default value of kSecTrustSettingsResultTrustRoot is assumed. Because only a root certificate can have this value, a usage constraints dictionary for a non-root certificate that is missing this key is not valid.
                    // Note the distinction between the results kSecTrustSettingsResultTrustRoot and kSecTrustSettingsResultTrustAsRoot: The former can only be applied to a root (self-signed) certificates; the latter can only be applied to non-root certificates. Therefore, an empty trust settings array for a non-root certificate is invalid, because the default value of kSecTrustSettingsResultTrustRoot is not valid for a non-root certificate.

                    SecurityFramework.SecTrustSettingsResult result;
                    if (value == null) {
                        result = SecurityFramework.SecTrustSettingsResult.kSecTrustSettingsResultTrustRoot;
                    } else {
                        CoreFoundation.CFNumberRef resultNumber = new CoreFoundation.CFNumberRef(value);
                        result = new SecurityFramework.SecTrustSettingsResult(resultNumber.longValue());
                        processedConstrains++;
                    }

                    // Return only trust roots. Skip even SecurityFramework.SecTrustSettingsResult.kSecTrustSettingsResultTrustAsRoot for now
                    if (!result.equals(SecurityFramework.SecTrustSettingsResult.kSecTrustSettingsResultTrustRoot)) {
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
                    if (constraints.getValue(SecurityFramework.kSecTrustSettingsAllowedError) != null) {
                        processedConstrains++;
                    }
                }

                // kSecTrustSettingsPolicyName
                {
                    // Skip kSecTrustSettingsPolicyName, it does not matter for processing
                    if (constraints.getValue(SecurityFramework.kSecTrustSettingsPolicyName) != null) {
                        processedConstrains++;
                    }
                }

                // kSecTrustSettingsPolicy
                {
                    Pointer value = constraints.getValue(SecurityFramework.kSecTrustSettingsPolicy);
                    if (value != null) {
                        SecurityFramework.SecPolicyRef secPolicyRef = new SecurityFramework.SecPolicyRef(value);

                        CoreFoundation.CFDictionaryRef policyDictionaryRef = SecurityFramework.INSTANCE.SecPolicyCopyProperties(secPolicyRef);
                        try {
                            Pointer policyOid = policyDictionaryRef.getValue(SecurityFramework.kSecPolicyOid);
                            if (policyOid == null) {
                                // Must be present, so it's an invalid policy
                                continue;
                            }

                            CoreFoundation.CFStringRef policyOidStringRef = new CoreFoundation.CFStringRef(policyOid);
                            if (!CoreFoundationExt.INSTANCE.CFEqual(SecurityFramework.kSecPolicyAppleSSL, policyOidStringRef)) {
                                // Accept only kSecPolicyAppleSSL policy
                                continue;
                            }
                        } finally {
                            policyDictionaryRef.release();
                        }

                        processedConstrains++;
                    }
                }

                if (constraintsCount.longValue() == processedConstrains) {
                    // return only certificates with known and checked constraints attached to them
                    // this way we'll probably miss some valid trusted roots, but
                    // there is no way to evaluate other and possibly unknown constraints
                    return true;
                }
            }

            // No matched constraints => not a trusted root
            return false;
        } finally {
            CoreFoundation.CFArrayRef array = trustedSettingsRef.getArray();
            if (array != null) {
                array.release();
            }
        }
    }
}
