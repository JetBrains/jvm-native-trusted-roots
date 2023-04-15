package org.jetbrains.nativecerts;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.X509Certificate;

public class NativeTrustedRootsInternalUtilsTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    @Test
    public void testSM2Parsing() {
        byte[] bytes = NativeCertsTestUtil.getResourceBytes("/MeSince-SM2.cer");
        X509Certificate certificate = NativeTrustedRootsInternalUtils.parseCertificate(bytes);
        Assert.assertEquals("C=CN,O=MeSince Technology Limited,CN=MeSince Identity CA SM2", certificate.getSubjectDN().toString());
    }
}
