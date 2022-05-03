package org.jetbrains.nativecerts.linux;

import org.jetbrains.nativecerts.NativeCertsSetupLoggingRule;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Collection;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isLinux;

public class LinuxTrustedCertificatesUtilTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    @Test
    public void smoke() {
        Assume.assumeTrue(isLinux);

        Collection<X509Certificate> list = LinuxTrustedCertificatesUtil.getSystemCertificates();
        Assert.assertTrue(String.valueOf(list.size()), list.size() > 100);

        Assert.assertEquals(0, loggingRule.numberOfWarningsOrAbove());
    }
}
