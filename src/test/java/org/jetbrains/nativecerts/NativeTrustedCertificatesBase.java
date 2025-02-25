package org.jetbrains.nativecerts;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.jetbrains.nativecerts.NativeCertsTestUtil.isManualTestingEnabled;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

public abstract class NativeTrustedCertificatesBase {

    private static final String AUTH_TYPE = "RSA";
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    abstract void addTrustedRoot();
    abstract void addIntermediateCertificate();
    abstract void removeRootCert();
    abstract void removeIntermediateCert();
    abstract boolean supportsIntermediateCertificates();

    @Before
    public void before() {
        assumeTrue(isManualTestingEnabled);
    }

    @After
    public void afterTest() {
        assertEquals(0, loggingRule.numberOfWarningsOrAbove());
    }

    @Test
    public void leafSignedFromTrustedRootTrusts() throws CertificateException, InterruptedException {
        try {
            addTrustedRoot();

            X509TrustManager trustManager = NativeTrustedCertificates.getOperatingSystemTrustManager();
            if (trustManager == null) {
                fail("Trust manager not resolved");
            }

            trustManager.checkServerTrusted(
                    new X509Certificate[]{NativeCertsTestUtil.getTestCertificate("/mock-ca/leaf-from-root.crt")},
                    AUTH_TYPE
            );
        } finally {
            removeRootCert();
        }
    }

    @Test
    public void leafSignedFromTrustedIntermediateAndRootTrusts() throws CertificateException, InterruptedException {
        assumeTrue(supportsIntermediateCertificates());
        try {
            addTrustedRoot();

            // add trusted cert
            addIntermediateCertificate();

            X509TrustManager trustManager = NativeTrustedCertificates.getOperatingSystemTrustManager();
            if (trustManager == null) {
                fail("Trust manager not resolved");
            }

            trustManager.checkServerTrusted(
                    new X509Certificate[]{NativeCertsTestUtil.getTestCertificate("/mock-ca/leaf-from-intermediate.crt")},
                    AUTH_TYPE
            );
        } finally {
            removeRootCert();
            removeIntermediateCert();
        }
    }

    @Test(expected = CertificateException.class)
    public void leafSignedFromTrustedIntermediateWithoutRootTrustThrows() throws CertificateException {
        try {
            // add intermediate CA cert
            addIntermediateCertificate();

            X509TrustManager trustManager = NativeTrustedCertificates.getOperatingSystemTrustManager();
            if (trustManager == null) {
                fail("Trust manager not resolved");
            }

            trustManager.checkServerTrusted(
                    new X509Certificate[]{NativeCertsTestUtil.getTestCertificate("/mock-ca/leaf-from-intermediate.crt")},
                    AUTH_TYPE
            );
        } finally {
            removeIntermediateCert();
        }
    }

    @Test(expected = CertificateException.class)
    public void leafSignedFromNonTrustedIntermediateNonTrustedRootThrows() throws CertificateException {
        X509TrustManager trustManager = NativeTrustedCertificates.getOperatingSystemTrustManager();
        if (trustManager == null) {
            fail("Trust manager not resolved");
        }

        trustManager.checkServerTrusted(
                new X509Certificate[]{NativeCertsTestUtil.getTestCertificate("/mock-ca/leaf-from-intermediate.crt")},
                AUTH_TYPE
        );
    }

    @Test(expected = CertificateException.class)
    public void nonTrustedRootThrows() throws InterruptedException, CertificateException {
        X509TrustManager trustManager = NativeTrustedCertificates.getOperatingSystemTrustManager();
        if (trustManager == null) {
            fail("Trust manager not resolved");
        }

        trustManager.checkServerTrusted(
                new X509Certificate[]{NativeCertsTestUtil.getTestCertificate()},
                AUTH_TYPE
        );
    }
}
