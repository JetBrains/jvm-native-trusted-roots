package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeCertsSetupLoggingRule;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.ExitCodeHandling;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.combineLists;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcess;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcessAndGetExitCode;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcessGetStdout;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getCertificatePath;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificate;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificatePath;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.isManualTestingEnabled;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isMac;
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

    @Test
    public void enumerateSystemCertificates() {
        List<X509Certificate> trustedRoots = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.system);

        System.out.println(trustedRoots.size());
        for (X509Certificate root : trustedRoots) {
            System.out.println(root.getSubjectX500Principal().toString());
        }

        Assert.assertTrue("Expected >100 system roots", trustedRoots.size() > 100);

        Assert.assertTrue(
                "Expected some roots from 'Google Trust Services LLC'",
                trustedRoots.stream().anyMatch(crt ->
                        crt.getSubjectX500Principal().toString().contains("Google Trust Services LLC"))
        );
        Assert.assertTrue(
                "Expected some roots from 'VeriSign'",
                trustedRoots.stream().anyMatch(crt ->
                        crt.getSubjectX500Principal().toString().contains("VeriSign"))
        );
    }

    @Test
    public void addRealUserTrustedCertificate() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);
        customUserTrustedCertificateTest(null, "trustRoot", true, true);
    }

    @Test
    public void addRealUserTrustedCertificate_ssl_policy() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);
        customUserTrustedCertificateTest("ssl", "trustRoot", true, true);
    }

    @Test
    @Ignore("Failing due to accepting client cert as a valid, " +
            "fixed by calling SecPolicyCreateSSL(/* server */ true) " +
            "instead of SecPolicyCreateSSL(false)")
    public void skip_client_certificate() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);

        Path clientPath = getCertificatePath("/mock-ca/client.pem");
        Path intermediatePath = getCertificatePath("/mock-ca/intermediate-ca.pem");

        deleteAllKnownCertificates();

        try {
            Path loginKeyChain = getLoginKeyChain();
            addTrustedCertificate(loginKeyChain, getTestCertificatePath());
            addCertificate(loginKeyChain, intermediatePath);
            addCertificate(loginKeyChain, clientPath);
            Thread.sleep(2000L);

            // Verify getTrustedRoots doesn't return client cert
            List<X509Certificate> afterAdd = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            List<String> afterAddAliases = afterAdd.stream().map(crt -> crt.getSubjectX500Principal().toString()).toList();
            assertThat(afterAddAliases, hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA, O=JETBRAINS"));
            assertThat(afterAddAliases, hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA, O=JETBRAINS"));
            assertThat(afterAddAliases, not(hasItem("CN=JVM-CLIENT-CERT, O=JETBRAINS")));
            // but it's still verifiable
            assertTrue(verifyCert(clientPath, null));

            // assert cleanup
            assertTrue(deleteCert("JVM-CLIENT-CERT"));
        } finally {
            deleteAllKnownCertificates();
        }
    }

    private static void deleteAllKnownCertificates() {
        deleteCert("JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA");
        deleteCert("JVM-CLIENT-CERT");
        deleteCert("JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA");
    }

    @Test
    public void addRealUserTrustedCertificate_deny() throws Exception {
        Assume.assumeTrue(isManualTestingEnabled);

        // see https://github.com/golang/go/issues/24084
        customUserTrustedCertificateTest("ssl", "deny", false, false);
    }

    @Test
    public void supportForIntermediateCertificates() throws InterruptedException {
        Assume.assumeTrue(isManualTestingEnabled);

        Path intermediatePath = getCertificatePath("/mock-ca/intermediate-ca.pem");

        // remove just in case it was not cleaned up before
        deleteAllKnownCertificates();
        List<X509Certificate> beforeAdd = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
        List<String> beforeAddAliases = beforeAdd.stream().map(crt -> crt.getSubjectX500Principal().toString()).toList();
        assertThat(beforeAddAliases, not(hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA, O=JETBRAINS")));
        assertThat(beforeAddAliases, not(hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA, O=JETBRAINS")));

        try {
            Path loginKeyChain = getLoginKeyChain();

            // add root cert
            addTrustedCertificate(loginKeyChain, getTestCertificatePath());

            Thread.sleep(2000L);

            // add intermediate cert
            addCertificate(loginKeyChain, intermediatePath);

            // verify both certs are trusted
            List<X509Certificate> afterAdd = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            List<String> afterAddAliases = afterAdd.stream().map(crt -> crt.getSubjectX500Principal().toString()).toList();
            assertThat(afterAddAliases, hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA, O=JETBRAINS"));
            assertThat(afterAddAliases, hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA, O=JETBRAINS"));
            assertTrue(verifyCert(intermediatePath, null));
            assertTrue(verifyCert(getTestCertificatePath(), null));

            // remove root cert. Both root and intermediate should disappear
            assertTrue(removeTrustedCert(getTestCertificatePath()));
            Thread.sleep(2000L);
            assertFalse(verifyCert(intermediatePath, null));
            assertFalse(verifyCert(getTestCertificatePath(), null));

            List<X509Certificate> afterRootRemoval = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            List<String> afterRootRemovalAliases = afterRootRemoval.stream().map(crt -> crt.getSubjectX500Principal().toString()).toList();
            assertThat(afterRootRemovalAliases, not(hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA, O=JETBRAINS")));
            assertThat(afterRootRemovalAliases, not(hasItem("CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA, O=JETBRAINS")));

            // assert cleanup
            assertTrue(deleteCert("JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA"));
        } finally {
            deleteAllKnownCertificates();
        }
    }

    private static void addTrustedCertificate(Path loginKeyChain, Path certificatePath) {
        List<String> args = List.of(
                "/usr/bin/security",
                "add-trusted-cert",
                "-k", loginKeyChain.toString(),
                certificatePath.toString()
        );
        executeProcess(args);
    }

    private static @NotNull Path getLoginKeyChain() {
        return Path.of(System.getProperty("user.home"), "Library/Keychains/login.keychain-db");
    }

    /**
     * @param policy Policy constraint (ssl, smime, codeSign, IPSec, iChat, basic, swUpdate, pkgSign, pkinitClient, pkinitServer, eap).
     * @param resultType trustRoot|trustAsRoot|deny|unspecified
     */
    private void customUserTrustedCertificateTest(@Nullable String policy, String resultType, boolean shouldTrustCertificate, boolean shouldTrustPolicy) throws Exception {
        Path loginKeyChain = getLoginKeyChain();
        assertTrue(Files.isRegularFile(loginKeyChain));

        // cleanup just in case it was imported before
        deleteAllKnownCertificates();

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
            Assert.assertEquals(shouldTrustPolicy, verifyCert(getTestCertificatePath(), policy));

            String trustSettings = executeProcessGetStdout(ExitCodeHandling.ASSERT, "/usr/bin/security", "dump-trust-setting");
            Assert.assertTrue(trustSettings, trustSettings.contains("JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA"));

            List<X509Certificate> rootsAfter = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            assertEquals(shouldTrustCertificate, rootsAfter.contains(getTestCertificate()));

            assertTrue(removeTrustedCert(getTestCertificatePath()));
            // verify cert is async
            Thread.sleep(3000);
            Assert.assertFalse(verifyCert(getTestCertificatePath(), policy));

            List<X509Certificate> rootsAfterRemoval = SecurityFrameworkUtil.getTrustedRoots(SecurityFramework.SecTrustSettingsDomain.user);
            assertFalse(rootsAfterRemoval.contains(getTestCertificate()));
        } finally {
            deleteAllKnownCertificates();
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

    private static void addCertificate(Path loginKeyChain, Path certificatePath) {
        executeProcess(List.of(
                "/usr/bin/security",
                "add-certificates",
                "-k", loginKeyChain.toString(),
                certificatePath.toString()
        ));
    }

    private static boolean deleteCert(String commonName) {
        int rc = executeProcessAndGetExitCode(List.of(
                "/usr/bin/security",
                "delete-certificate",
                "-c", commonName,
                // Also delete user trust settings for this certificate
                "-t"
        ));
        return rc == 0;
    }
}
