package org.jetbrains.nativecerts.win32;

import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import org.jetbrains.nativecerts.NativeCertsSetupLoggingRule;
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
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getCertificatePath;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificate;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificatePath;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.isManualTestingEnabled;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isWindows;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.sha1hex;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class Crypt32ExtUtilTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    @BeforeClass
    public static void beforeClass() {
        Assume.assumeTrue("Requires Windows", isWindows);
    }

    /**
     * Mostly dumps current custom certificates, for a manual review and check that there is no failure
     */
    @Test
    public void smoke() {
        Collection<X509Certificate> certificates = Crypt32ExtUtil.getCustomTrustedRootCertificates();
        Assert.assertTrue(!certificates.isEmpty());
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

        Win32Exception notTrustedException = assertThrows(Win32Exception.class, () -> Crypt32ExtUtil.validateCertificate(encoded));
        assertEquals(WinError.CERT_E_UNTRUSTEDROOT, notTrustedException.getErrorCode());

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
            Crypt32ExtUtil.validateCertificate(encoded);

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

    @Test
    public void intermediateCACertsAreIncluded() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);

        X509Certificate rootCertificate = getTestCertificate();
        byte[] rootEncoded = rootCertificate.getEncoded();
        String sha1Root = sha1hex(rootEncoded);

        String intermediateCertResourcePath = "/mock-ca/intermediate-ca.pem";
        X509Certificate intermediateCertificate = getTestCertificate(intermediateCertResourcePath);
        byte[] intermediateEncoded = intermediateCertificate.getEncoded();
        String sha1Intermediate = sha1hex(intermediateEncoded);

        // cleanup just in case it was imported before
        removeTrustedCert(sha1Root);
        removeTrustedCert(sha1Intermediate, "CA");

        try {
            Collection<X509Certificate> rootsBefore = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            assertFalse(rootsBefore.contains(rootCertificate));
            assertFalse(rootsBefore.contains(intermediateCertificate));
            assertFalse(verifyCert(sha1Root));

            executeProcess(
                    List.of("certutil", "-user", "-addstore", "Root", getTestCertificatePath().toString())
            );
            assertTrue(verifyCert(sha1Root));

            String intermediateCertPath = getCertificatePath(intermediateCertResourcePath).toString();
            executeProcess(
                    List.of("certutil", "-user", "-addstore", "CA", intermediateCertPath)
            );

            Collection<X509Certificate> rootsAfter = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            assertTrue(rootsAfter.contains(rootCertificate));
            assertTrue(rootsAfter.contains(intermediateCertificate));
            Crypt32ExtUtil.validateCertificate(intermediateEncoded);

            // Remove only root
            assertTrue(removeTrustedCert(sha1Root));
            Assert.assertFalse(verifyCert(sha1Root));

            // intermediate certificate should not be accepted after removing root
            Collection<X509Certificate> rootsAfterRootRemoval = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            assertFalse(rootsAfterRootRemoval.contains(rootCertificate));
            assertFalse(rootsAfterRootRemoval.contains(intermediateCertificate));
            var noTrustedRoot = assertThrows(Win32Exception.class, () -> Crypt32ExtUtil.validateCertificate(intermediateEncoded));
            assertEquals(WinError.CERT_E_UNTRUSTEDROOT, noTrustedRoot.getErrorCode());

            // Remove intermediate too
            assertTrue(removeTrustedCert(sha1Intermediate, "CA"));
            Assert.assertFalse(verifyCert(sha1Intermediate));

            // Check that cleanup was successful
            Collection<X509Certificate> rootsAfterRemoval = Crypt32ExtUtil.getCustomTrustedRootCertificates();
            assertFalse(rootsAfterRemoval.contains(rootCertificate));
            assertFalse(rootsAfterRemoval.contains(intermediateCertificate));
        } finally {
            // always clean-up
            removeTrustedCert(sha1Root);
            removeTrustedCert(sha1Intermediate);
        }
    }

    private boolean removeTrustedCert(String sha1) {
        return removeTrustedCert(sha1, "Root");
    }

    private boolean removeTrustedCert(String sha1, String store) {
        String out = executeProcessGetStdout(ExitCodeHandling.ASSERT, "certutil", "-user", "-delstore", store, sha1);
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
