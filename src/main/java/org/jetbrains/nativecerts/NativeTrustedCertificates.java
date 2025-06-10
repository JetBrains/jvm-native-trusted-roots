package org.jetbrains.nativecerts;

import org.jetbrains.nativecerts.linux.LinuxTrustedCertificatesUtil;
import org.jetbrains.nativecerts.mac.SecurityFrameworkUtil;
import org.jetbrains.nativecerts.win32.Crypt32ExtUtil;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Logger;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isLinux;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isMac;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isWindows;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;

public class NativeTrustedCertificates {
    private static final Logger LOGGER = Logger.getLogger(NativeTrustedCertificates.class.getName());

    /**
     * Get custom trusted certificates from the operating system.
     * Uses platform-specific APIs. Does not fail, only logs to java util logging.
     * On some systems (currently, Linux) may return an entire set of trusted certificates.
     * <p>
     * To get more logging on user's machine enable FINE logging level for {@code org.jetbrains.nativecerts} category.
     * </p>
     * @return custom trusted certificates collection or an empty collection in case of failure
     */
    public static Collection<X509Certificate> getCustomOsSpecificTrustedCertificates() {
        try {
            if (isLinux) {
                return LinuxTrustedCertificatesUtil.getSystemCertificates();
            }

            if (isMac) {
                List<X509Certificate> admin = SecurityFrameworkUtil.getTrustedRoots();
                return new HashSet<>(admin);
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
}
