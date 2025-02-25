package org.jetbrains.nativecerts;

import org.junit.Assume;
import org.junit.BeforeClass;

import java.nio.file.Path;
import java.util.List;

import static org.jetbrains.nativecerts.NativeCertsTestUtil.executeProcess;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getCertificatePath;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificatePath;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isMac;

public class NativeTrustedCertificatesMacTest extends NativeTrustedCertificatesBase {

    private static final Path LOGIN_KEY_CHAIN = Path.of(System.getProperty("user.home"), "Library/Keychains/login.keychain-db");

    @BeforeClass
    public static void beforeClass() {
        Assume.assumeTrue("Requires Mac OS X", isMac);
    }

    void addIntermediateCertificate() {
        List<String> args = List.of(
                "/usr/bin/security",
                "add-certificates",
                "-k", LOGIN_KEY_CHAIN.toString(),
                getCertificatePath("/mock-ca/intermediate-ca.pem").toString()
        );
        executeProcess(args);
    }

    void addTrustedRoot() {
        List<String> args = List.of(
                "/usr/bin/security",
                "add-trusted-cert",
                "-k", LOGIN_KEY_CHAIN.toString(),
                getTestCertificatePath().toString()
        );
        executeProcess(args);

        try {
            Thread.sleep(2000L);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    void removeRootCert() {
        removeCert("JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA");
    }

     void removeIntermediateCert() {
            removeCert("JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA");
    }

    private static void removeCert(String identifier) {
        executeProcess(
                List.of(
                        "/usr/bin/security",
                        "delete-certificate",
                        "-c", identifier,
                        "-t"
                )
        );
    }

    boolean supportsIntermediateCertificates() {
        return false;
    }
}
