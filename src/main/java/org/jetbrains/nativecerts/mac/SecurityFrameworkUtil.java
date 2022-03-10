package org.jetbrains.nativecerts.mac;

import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

public class SecurityFrameworkUtil {
    @NotNull
    public static List<X509Certificate> SecTrustSettingsCopyCertificates(
            @NotNull SecurityFramework.SecTrustSettingsDomain domain,
            Predicate<SecurityFramework.SecCertificateRef> predicate) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        CFArrayRefByReference returnedCertArray = new CFArrayRefByReference();
        SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecTrustSettingsCopyCertificates(domain, returnedCertArray);
        if (rc == SecurityFramework.OSStatus.errSecNoTrustSettings) {
            return Collections.emptyList();
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

                CoreFoundation.CFDataRef data = SecurityFramework.INSTANCE.SecCertificateCopyData(secCertificateRef);
                try {
                    byte[] bytes = data.getBytePtr().getByteArray(0, data.getLength());

                    X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
                    result.add(certificate);
                } finally {
                    data.release();
                }
            }

            return result;
        } finally {
            certArray.release();
        }
    }

    public static boolean isTrustedRoot(SecurityFramework.SecTrustSettingsDomain domain, SecurityFramework.SecCertificateRef certificateRef) {
        CFArrayRefByReference trustedSettingsRef = new CFArrayRefByReference();
        SecurityFramework.OSStatus rc = SecurityFramework.INSTANCE.SecTrustSettingsCopyTrustSettings(certificateRef, domain, trustedSettingsRef);

        CoreFoundation.CFArrayRef trustedSettingsArray = trustedSettingsRef.getArray();
        if (rc == SecurityFramework.OSStatus.errSecItemNotFound || trustedSettingsArray == null) {
            // No trust record => do not trust
            return false;
        }

        try {
            if (trustedSettingsArray.getCount() == 0) {
                // https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting
                // An empty trust settings array (that is, the trustSettings parameter returns a valid but empty CFArray) means "always trust this certificate” with an overall trust setting for the certificate of kSecTrustSettingsResultTrustRoot
                return true;
            }

            for (int i = 0; i < trustedSettingsArray.getCount(); i++) {
                CoreFoundation.CFDictionaryRef constraints = new CoreFoundation.CFDictionaryRef(trustedSettingsArray.getValueAtIndex(i));

                Pointer value = constraints.getValue(SecurityFramework.INSTANCE.kSecTrustSettingsResult);
                if (value == null) {
                    // a constraint without a result => skip
                    continue;
                }

                CoreFoundation.CFIndex constraintsCount = CoreFoundationExt.INSTANCE.CFDictionaryGetCount(constraints);
                if (constraintsCount.longValue() != 1) {
                    // Follow the policy as dotnet/runtime now:
                    // return only certificates without constraints attached for them
                    // this way we'll probably miss some valid trusted roots, but
                    // there is no way to evaluate constraints
                    continue;
                }

                CoreFoundation.CFNumberRef resultNumber = new CoreFoundation.CFNumberRef(value);
                SecurityFramework.SecTrustSettingsResult result = new SecurityFramework.SecTrustSettingsResult(resultNumber.longValue());

                // Return only trust roots. Skip even SecurityFramework.SecTrustSettingsResult.kSecTrustSettingsResultTrustAsRoot for now
                if (result == SecurityFramework.SecTrustSettingsResult.kSecTrustSettingsResultTrustRoot) {
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
