package org.jetbrains.nativecerts.mac;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;

public class SecurityFrameworkUtilTest {
    @Test
    public void enumerateSystemCertificates() throws Exception {
        Assume.assumeTrue("Requires Mac OS X", System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("mac"));

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
}
