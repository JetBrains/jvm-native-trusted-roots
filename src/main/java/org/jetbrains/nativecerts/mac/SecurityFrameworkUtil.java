package org.jetbrains.nativecerts.mac;

import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;

/**
 * Get trusted certificates stored in corresponding keychains via Security frameworks APIs.
 * for the other implementations see root_cgo_darwin.go in Go and trust_store_mac.cc in Chromium
 * <br><br>
 * In the future it would be better to implement {@code X509TrustManager} on <a href="https://developer.apple.com/documentation/security/2980705-sectrustevaluatewitherror">SecTrustEvaluateWithError</a> instead
 * of getting trust chain manually. It's not yet investigated whether it is possible at all to integrate it into
 * the SSL framework of JVM.
 */
public class SecurityFrameworkUtil {
    private final static Logger LOGGER = Logger.getLogger(SecurityFrameworkUtil.class.getName());

    public static List<X509Certificate> getTrustedRoots(SecurityFramework.SecTrustSettingsDomain domain) {
        List<X509Certificate> result = SecTrustSettingsCopyCertificates(domain, cert -> isTrustedRoot(domain, cert));

        if (LOGGER.isLoggable(Level.FINE)) {
            StringBuilder message = new StringBuilder();
            message.append("Received ").append(result.size()).append(" certificates from trust settings domain ").append(domain);

            for (X509Certificate certificate : result) {
                message.append("\n  ").append(certificate.getSubjectDN());
            }

            LOGGER.fine(message.toString());
        }

        return result;
    }

    @NotNull
    public static List<X509Certificate> SecTrustSettingsCopyCertificates(
            @NotNull SecurityFramework.SecTrustSettingsDomain domain,
            Predicate<SecurityFramework.SecCertificateRef> predicate) {
        CFArrayRefByReference returnedCertArray = new CFArrayRefByReference();
        SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecTrustSettingsCopyCertificates(domain, returnedCertArray);
        if (SecurityFramework.OSStatus.errSecNoTrustSettings.equals(rc)) {
            return Collections.emptyList();
        }

        if (!SecurityFramework.OSStatus.errSecSuccess.equals(rc)) {
            throw new IllegalStateException("Getting trust settings for domain " + domain +
                    " failed: " + rc);
        }

        CoreFoundation.CFArrayRef certArray = returnedCertArray.getArray();
        if (certArray == null) {
            return Collections.emptyList();
        }

        try {
            List<X509Certificate> result = new ArrayList<>();

            for (int i = 0; i < certArray.getCount(); i++) {
                SecurityFramework.SecCertificateRef secCertificateRef = new SecurityFramework.SecCertificateRef(certArray.getValueAtIndex(i));
                if (!predicate.test(secCertificateRef)) {
                    continue;
                }

                result.add(getX509Certificate(secCertificateRef));
            }

            return result;
        } finally {
            certArray.release();
        }
    }

    private static X509Certificate getX509Certificate(SecurityFramework.SecCertificateRef secCertificateRef) {
        CoreFoundation.CFDataRef data = SecurityFramework.INSTANCE.SecCertificateCopyData(secCertificateRef);
        try {
            byte[] bytes = data.getBytePtr().getByteArray(0, data.getLength());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
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

    public static boolean isTrustedRoot(SecurityFramework.SecTrustSettingsDomain domain, SecurityFramework.SecCertificateRef certificateRef) {
        boolean selfSignedCertificate = isSelfSignedCertificate(getX509Certificate(certificateRef));

        CFArrayRefByReference trustedSettingsRef = new CFArrayRefByReference();
        SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecTrustSettingsCopyTrustSettings(certificateRef, domain, trustedSettingsRef);

        CoreFoundation.CFArrayRef trustedSettingsArray = trustedSettingsRef.getArray();
        if (SecurityFramework.OSStatus.errSecItemNotFound.equals(rc) || trustedSettingsArray == null) {
            // No trust record => do not trust
            return false;
        }

        String certificateDescription = CoreFoundation.INSTANCE.CFCopyDescription(certificateRef).stringValue();

        if (LOGGER.isLoggable(Level.FINE)) {
            try {
                CoreFoundation.CFStringRef cfStringRef = CoreFoundation.INSTANCE.CFCopyDescription(trustedSettingsArray);
                LOGGER.fine("Certificate '" + certificateDescription + "' trusted settings:\n" + cfStringRef.stringValue());
            } catch (Throwable t) {
                LOGGER.warning(renderExceptionMessage("Unable to describe certificate trusted settings", t));
            }
        }

        try {
            if (trustedSettingsArray.getCount() == 0) {
                // https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting
                // An empty trust settings array (that is, the trustSettings parameter returns a valid but empty CFArray) means "always trust this certificate” with an overall trust setting for the certificate of kSecTrustSettingsResultTrustRoot
                return true;
            }

            for (int i = 0; i < trustedSettingsArray.getCount(); i++) {
                CoreFoundation.CFDictionaryRef constraints = new CoreFoundation.CFDictionaryRef(trustedSettingsArray.getValueAtIndex(i));
                CoreFoundation.CFIndex constraintsCount = CoreFoundationExt.INSTANCE.CFDictionaryGetCount(constraints);
                int processedConstrains = 0;

                // kSecTrustSettingsResult
                {
                    Pointer value = constraints.getValue(SecurityFramework.INSTANCE.kSecTrustSettingsResult);

                    // from https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting
                    // If this key is not present, a default value of kSecTrustSettingsResultTrustRoot is assumed. Because only a root certificate can have this value, a usage constraints dictionary for a non-root certificate that is missing this key is not valid.
                    // Note the distinction between the results kSecTrustSettingsResultTrustRoot and kSecTrustSettingsResultTrustAsRoot: The former can only be applied to root (self-signed) certificates; the latter can only be applied to non-root certificates. Therefore, an empty trust settings array for a non-root certificate is invalid, because the default value of kSecTrustSettingsResultTrustRoot is not valid for a non-root certificate.

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
                    if (constraints.getValue(SecurityFramework.INSTANCE.kSecTrustSettingsAllowedError) != null) {
                        processedConstrains++;
                    }
                }

                // kSecTrustSettingsPolicyName
                {
                    // Skip kSecTrustSettingsPolicyName, it does not matter for processing
                    if (constraints.getValue(SecurityFramework.INSTANCE.kSecTrustSettingsPolicyName) != null) {
                        processedConstrains++;
                    }
                }

                // kSecTrustSettingsPolicy
                {
                    Pointer value = constraints.getValue(SecurityFramework.INSTANCE.kSecTrustSettingsPolicy);
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
            trustedSettingsArray.release();
        }
    }
}
