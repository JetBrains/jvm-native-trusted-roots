package org.jetbrains.nativecerts;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class NativeTrustedRootsInternalUtilsTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    @Test
    public void testSM2Parsing() {
        byte[] bytes = NativeCertsTestUtil.getResourceBytes("/MeSince-SM2.cer");
        X509Certificate certificate = NativeTrustedRootsInternalUtils.parseCertificate(bytes);
        Assert.assertEquals("org.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateObject", certificate.getClass().getName());
        Assert.assertEquals("C=CN,O=MeSince Technology Limited,CN=MeSince Identity CA SM2", certificate.getSubjectDN().toString());
    }

    @Test
    public void test16kRSA() {
        byte[] bytes = NativeCertsTestUtil.getResourceBytes("/16k-rsa-example-cert.der");
        X509Certificate certificate = NativeTrustedRootsInternalUtils.parseCertificate(bytes);
        // bundled JRE parses 16k
        Assert.assertEquals("sun.security.x509.X509CertImpl", certificate.getClass().getName());
        Assert.assertEquals("CN=www.example.com, O=Frank4DD, ST=Tokyo, C=JP", certificate.getSubjectDN().toString());
    }

    @Test
    public void test16kRSA_bouncy_castle_fail() throws CertificateException {
        byte[] bytes = NativeCertsTestUtil.getResourceBytes("/16k-rsa-example-cert.der");
        // BouncyCastle fails to do so by default
        CertificateFactory bcProvider = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        try {
            NativeTrustedRootsInternalUtils.parseCertificate(bytes, bcProvider);
        } catch (IllegalArgumentException e) {
            Assert.assertEquals("modulus value out of range", e.getMessage());
        }
    }
}
