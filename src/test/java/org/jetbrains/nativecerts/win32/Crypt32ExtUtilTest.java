package org.jetbrains.nativecerts.win32;

import org.jetbrains.nativecerts.NativeCertsSetupLoggingRule;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Collection;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isWindows;

public class Crypt32ExtUtilTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    /**
     * Mostly dumps current custom certificates, for a manual review and check that there is no failure
     */
    @Test
    public void test() throws Exception {
        Assume.assumeTrue("Requires Windows", isWindows);

        Collection<X509Certificate> certificates = Crypt32ExtUtil.getCustomTrustedRootCertificates();
        Assert.assertTrue(certificates.size() > 0);
        Assert.assertTrue(certificates.stream().anyMatch(c -> c.getSubjectDN().toString().contains("Microsoft ")));

        for (X509Certificate certificate : certificates) {
            System.out.println("Received custom trusted certificate: " + certificate.getSubjectDN());
        }

        Assert.assertEquals(0, loggingRule.numberOfWarningsOrAbove());
    }
}
