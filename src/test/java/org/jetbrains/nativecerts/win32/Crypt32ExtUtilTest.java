package org.jetbrains.nativecerts.win32;

import org.jetbrains.nativecerts.NativeCertsSetupLoggingRule;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import static org.jetbrains.nativecerts.NativeCertsTestUtil.ExitCodeHandling;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcess;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcessGetStdout;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificate;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificatePath;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.isManualTestingEnabled;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.sha1hex;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.sha256hex;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isWindows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class Crypt32ExtUtilTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    @BeforeClass
    public static void beforeClass() {
        Assume.assumeTrue("Requires Windows", isWindows);
    }

    @After
    public void afterTest() {
        assertEquals(0, loggingRule.numberOfWarningsOrAbove());
    }

    /**
     * Mostly dumps current custom certificates, for a manual review and check that there is no failure
     */
    @Test
    public void smoke() throws Exception {
        Collection<X509Certificate> certificates = Crypt32ExtUtil.getCustomTrustedRootCertificates();
        Assert.assertTrue(certificates.size() > 0);
        Assert.assertTrue(certificates.stream().anyMatch(c -> c.getSubjectDN().toString().contains("Microsoft ")));

        for (X509Certificate certificate : certificates) {
            System.out.println("Received custom trusted certificate: " + certificate.getSubjectDN());
        }
    }

    @Test
    public void realUserTrustedCertificateTest() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);

        byte[] encoded = getTestCertificate().getEncoded();
        String sha1 = sha1hex(encoded);
        String sha256 = sha256hex(encoded);
        assertEquals("a2133a948547091abc0e0f62aa27bb1927b03f10", sha1);
        //noinspection SpellCheckingInspection
        assertEquals("d5976cf01a27686e61c1ab79907ceed01a9d74a5c7495aad617a7df88fbec204", sha256);

        // cleanup just in case it was imported before
        removeTrustedCert(sha1);

        try {
            Collection<X509Certificate> rootsBefore = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            assertFalse(rootsBefore.contains(getTestCertificate()));

            Assert.assertFalse(verifyCert(sha1));

            executeProcess(
                    List.of("certutil", "-user", "-addstore", "Root", getTestCertificatePath().toString())
            );
            assertTrue(verifyCert(sha1));

            Collection<X509Certificate> rootsAfter = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            assertTrue(rootsAfter.contains(getTestCertificate()));

            assertTrue(removeTrustedCert(sha1));
            Assert.assertFalse(verifyCert(sha1));

            Collection<X509Certificate> rootsAfterRemoval = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            assertFalse(rootsAfterRemoval.contains(getTestCertificate()));
        } finally {
            // always clean-up
            removeTrustedCert(sha1);
        }
    }

    private boolean removeTrustedCert(String sha1) {
        String out = executeProcessGetStdout(ExitCodeHandling.ASSERT, "certutil", "-user", "-delstore", "Root", sha1);
        return out.contains("Deleting Certificate");
    }

    private boolean verifyCert(String sha1) {
        String out = executeProcessGetStdout(ExitCodeHandling.IGNORE, "certutil", "-user", "-verifystore", "Root", sha1);
        if (out.contains("Certificate is valid") && out.contains("command completed successfully")) {
            return true;
        }

        if (out.contains("Object was not found")) {
            return false;
        }

        throw new IllegalStateException("Unrecognized certutil output: " + out);
    }
}
