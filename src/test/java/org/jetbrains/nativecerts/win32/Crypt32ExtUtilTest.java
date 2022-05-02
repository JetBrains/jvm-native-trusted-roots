package org.jetbrains.nativecerts.win32;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Locale;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class Crypt32ExtUtilTest {
    /**
     * Mostly dumps current custom certificates, for a manual review and check that there is no failure
     */
    @Test
    public void test() throws Exception {
        Assume.assumeTrue("Requires Windows", System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("win"));

        final ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.FINEST);
        consoleHandler.setFormatter(new SimpleFormatter());

        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.FINE);
        rootLogger.addHandler(consoleHandler);

        try {
            Collection<X509Certificate> certificates = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            Assert.assertTrue(certificates.size() > 0);
            Assert.assertTrue(certificates.stream().anyMatch(c -> c.getSubjectDN().toString().contains("Microsoft ")));

            for (X509Certificate certificate : certificates) {
                System.out.println("Received custom trusted certificate: " + certificate.getSubjectDN());
            }
        } finally {
            rootLogger.removeHandler(consoleHandler);
        }
    }
}
