package org.jetbrains.nativecerts;

import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.linux.LinuxTrustedCertificatesUtil;
import org.jetbrains.nativecerts.mac.SecurityFramework;
import org.jetbrains.nativecerts.mac.SecurityFrameworkUtil;
import org.jetbrains.nativecerts.win32.Crypt32ExtUtil;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.*;

public class NativeTrustedCertificates {
    private static final Logger LOGGER = Logger.getLogger(NativeTrustedCertificates.class.getName());

    /**
     * Get custom trusted certificates from the operating system.
     * Uses platform-specific APIs. Does not fail, only logs to java util logging.
     * On some systems (currently, Linux) may return an entire set of trusted certificates.
     * <p>
     * To get more logging on user's machine enable FINE logging level for {@code org.jetbrains.nativecerts} category.
     * </p>
     *
     * @return custom trusted certificates collection or an empty collection in case of failure
     */
    public static Collection<X509Certificate> getCustomOsSpecificTrustedCertificates() {
        try {
            if (isLinux) {
                return LinuxTrustedCertificatesUtil.getSystemCertificates();
            }

            if (isMac) {
                List<X509Certificate> admin = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.admin);
                List<X509Certificate> user = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);

                Set<X509Certificate> result = new HashSet<>(admin);
                result.addAll(user);
                return result;
            }

            if (isWindows) {
                return Crypt32ExtUtil.getCustomTrustedRootCertificates();
            }

            LOGGER.warning("Unable to get custom trusted certificates list from the operating system: unsupported system, not a Linux/Mac OS/Windows: " + System.getProperty("os.name"));
            return Collections.emptySet();
        } catch (Throwable t) {
            LOGGER.warning(renderExceptionMessage("Unable to get custom trusted certificates list from the operating system", t));
            return Collections.emptySet();
        }
    }

    /**
     * Get an {@link X509TrustManager} backed by trusted certificates from the operating system.
     *
     * @return a trust manager or {@code null} if the operating system does not provide any custom trusted certificates.
     */
    public static @Nullable X509TrustManager getOperatingSystemTrustManager() {
        try {
            Collection<X509Certificate> additionalTrustedCertificates = getCustomOsSpecificTrustedCertificates();
            if (additionalTrustedCertificates.isEmpty()) {
                return null;
            }

            X509TrustManager x509TrustManager = createTrustManagerFromCertificates(additionalTrustedCertificates);

            String acceptedRoots =
                    Arrays.stream(x509TrustManager.getAcceptedIssuers())
                            .map(certificate -> certificate.getSubjectX500Principal().toString())

                            .sorted()
                            .collect(Collectors.joining("\n"));
            LOGGER.fine("Accepted trusted certificate roots from the system: \n" + acceptedRoots);

            return x509TrustManager;
        } catch (Throwable exception) {
            LOGGER.log(Level.SEVERE, "Unable to build system trusted certificates manager: " + exception.getMessage(), exception);
            return null;
        }
    }

    private static @NotNull X509TrustManager createTrustManagerFromCertificates(@NotNull Collection<? extends X509Certificate> certificates) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        for (X509Certificate certificate : certificates) {
            ks.setCertificateEntry(
                    certificate.getSubjectX500Principal().toString() + "-" +
                            NativeTrustedRootsInternalUtils
                                    .sha256hex(certificate.getEncoded()), certificate);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        List<X509TrustManager> x509TrustManagers = toX509TrustManager(tmf.getTrustManagers());
        if (x509TrustManagers.isEmpty()) {
            throw new IllegalStateException("Unable to create X509TrustManager from keystore: no X509TrustManager instances returned, only " +
                    Arrays.toString(tmf.getTrustManagers()));
        }
        if (x509TrustManagers.size() > 1) {
            throw new IllegalStateException(
                    "Unable to create X509TrustManager from keystore: more than one X509TrustManager instance returned: " + x509TrustManagers);
        }

        return x509TrustManagers.get(0);
    }

    private static List<X509TrustManager> toX509TrustManager(TrustManager[] trustManagers) {
        return Arrays.stream(trustManagers)
                .filter(X509TrustManager.class::isInstance)
                .map(X509TrustManager.class::cast)
                .toList();
    }
}
