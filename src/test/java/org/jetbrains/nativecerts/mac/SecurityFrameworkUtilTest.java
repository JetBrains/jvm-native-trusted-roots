package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeCertsSetupLoggingRule;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.jetbrains.nativecerts.NativeCertsTestUtil.ExitCodeHandling;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.combineLists;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcess;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcessAndGetExitCode;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcessGetStdout;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificate;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificatePath;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.isManualTestingEnabled;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isMac;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.sha1hex;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.sha256hex;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecurityFrameworkUtilTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    @BeforeClass
    public static void beforeClass() {
        Assume.assumeTrue("Requires Mac OS X", isMac);
    }

    @After
    public void afterTest() {
        assertEquals(0, loggingRule.numberOfWarningsOrAbove());
    }

    @Test
    public void enumerateSystemCertificates() {
        List<X509Certificate> trustedRoots = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.system);

        System.out.println(trustedRoots.size());
        for (X509Certificate root : trustedRoots) {
            System.out.println(root.getSubjectDN().toString());
        }

        Assert.assertTrue("Expected >100 system roots", trustedRoots.size() > 100);

        Assert.assertTrue(
                "Expected some roots from 'Google Trust Services LLC'",
                trustedRoots.stream().anyMatch(crt ->
                        crt.getSubjectDN().toString().contains("Google Trust Services LLC"))
        );
        Assert.assertTrue(
                "Expected some roots from 'VeriSign'",
                trustedRoots.stream().anyMatch(crt ->
                        crt.getSubjectDN().toString().contains("VeriSign"))
        );
    }

    @Test
    public void addRealUserTrustedCertificate() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);
        customUserTrustedCertificateTest(null, "trustRoot", true);
    }

    @Test
    public void addRealUserTrustedCertificate_ssl_policy() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);
        customUserTrustedCertificateTest("ssl", "trustRoot", true);
    }

    @Test
    public void addRealUserTrustedCertificate_deny() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);

        // see https://github.com/golang/go/issues/24084
        customUserTrustedCertificateTest("ssl", "deny", false);
    }

    /**
     * @param policy Policy constraint (ssl, smime, codeSign, IPSec, iChat, basic, swUpdate, pkgSign, pkinitClient, pkinitServer, eap).
     * @param resultType trustRoot|trustAsRoot|deny|unspecified
     */
    private void customUserTrustedCertificateTest(@Nullable String policy, String resultType, boolean shouldTrust) throws Exception {
        Path loginKeyChain = Path.of(System.getProperty("user.home"), "Library/Keychains/login.keychain-db");
        assertTrue(Files.isRegularFile(loginKeyChain));

        byte[] encoded = getTestCertificate().getEncoded();
        String sha1 = sha1hex(encoded);
        String sha256 = sha256hex(encoded);
        assertEquals("a2133a948547091abc0e0f62aa27bb1927b03f10", sha1);
        //noinspection SpellCheckingInspection
        assertEquals("d5976cf01a27686e61c1ab79907ceed01a9d74a5c7495aad617a7df88fbec204", sha256);

        // cleanup just in case it was imported before
        removeTrustedCert(getTestCertificatePath());

        try {
            List<X509Certificate> rootsBefore = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            assertFalse(rootsBefore.contains(getTestCertificate()));

            Assert.assertFalse(verifyCert(getTestCertificatePath(), policy));

            executeProcess(
                    combineLists(
                            List.of("/usr/bin/security", "add-trusted-cert"),
                            policy == null ? Collections.emptyList() : List.of("-p", policy),
                            List.of("-r", resultType, "-k", loginKeyChain.toString(), getTestCertificatePath().toString())
                    )
            );

            // verify cert is async
            Thread.sleep(3000);
            Assert.assertEquals(shouldTrust, verifyCert(getTestCertificatePath(), policy));

            String trustSettings = executeProcessGetStdout(ExitCodeHandling.ASSERT, "/usr/bin/security", "dump-trust-setting");
            Assert.assertTrue(trustSettings, trustSettings.contains("certificates-tests.labs.intellij.net"));

            List<X509Certificate> rootsAfter = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            assertEquals(shouldTrust, rootsAfter.contains(getTestCertificate()));

            assertTrue(removeTrustedCert(getTestCertificatePath()));
            // verify cert is async
            Thread.sleep(3000);
            Assert.assertFalse(verifyCert(getTestCertificatePath(), policy));

            List<X509Certificate> rootsAfterRemoval = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            assertFalse(rootsAfterRemoval.contains(getTestCertificate()));
        } finally {
            // even if test fails we must remove trusted certificate
            removeTrustedCert(getTestCertificatePath());
        }
    }

    @Test
    public void testCertificateIsSelfSigned() {
        assertTrue(SecurityFrameworkUtil.isSelfSignedCertificate(getTestCertificate()));
    }

    private static boolean verifyCert(Path cert, @Nullable String policy) {
        // https://www.unix.com/man-page/osx/1/security
        // -l Specifies that the leaf certificate is a CA cert. By default, a leaf certificate
        //    with a Basic Constraints extension with the CA bit set fails verification.
        // -L Use local certificates only. If an issuing CA certificate is missing, this option will
        //    avoid accessing the network to fetch it.
        // -c Certificate to verify, in DER or PEM format. Can be specified more than once;
        //    leaf certificate has to be specified first.
        // -p Specify verification policy (ssl, smime, codeSign, IPSec, iChat, basic, swUpdate, pkgSign,
        //    pkinitClient, pkinitServer, eap, appleID, macappstore, timestamping). Default is basic.
        int rc = executeProcessAndGetExitCode(
                combineLists(
                        List.of("/usr/bin/security", "verify-cert"),
                        policy == null ? Collections.emptyList() : List.of("-p", policy),
                        List.of( "-l", "-L", "-c", cert.toAbsolutePath().toString())
                )
        );
        return rc == 0;
    }

    private static boolean removeTrustedCert(Path cert) {
        int rc = executeProcessAndGetExitCode(List.of("/usr/bin/security", "remove-trusted-cert", cert.toAbsolutePath().toString()));
        return rc == 0;
    }
}
