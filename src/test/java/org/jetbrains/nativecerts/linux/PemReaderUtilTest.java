package org.jetbrains.nativecerts.linux;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.sha256hex;

public class PemReaderUtilTest {
    @Test
    public void unfinishedBlock() throws CertificateException, IOException {
        @SuppressWarnings("SpellCheckingInspection")
        String data = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlDCCAnygAwIBAgIKMfXkYgxsWO3W2DANBgkqhkiG9w0BAQsFADBnMQswCQYD\n" +
                "VQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBU\n" +
                "ZWNobm9sb2dpZXMgTGltaXRlZDEcMBoGA1UEAxMTZW1TaWduIFJvb3QgQ0EgLSBH\n";

        try {
            PemReaderUtil.readPemBundle(new ByteArrayInputStream(data.getBytes(StandardCharsets.US_ASCII)), "test");
        } catch (IllegalStateException t) {
            Assert.assertEquals("Non-closed '-----BEGIN CERTIFICATE-----' block at line 4 : test", t.getMessage());
        }
    }

    @Test
    public void wrongBlock() throws CertificateException, IOException {
        @SuppressWarnings("SpellCheckingInspection")
        String data = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIDlDCCAnygAwIBAgIKMfXkYgxsWO3W2DANBgkqhkiG9w0BAQsFADBnMQswCQYD\n" +
                "-----END PRIVATE KEY-----\n";

        try {
            PemReaderUtil.readPemBundle(new ByteArrayInputStream(data.getBytes(StandardCharsets.US_ASCII)), "test");
        } catch (IllegalStateException t) {
            Assert.assertEquals("Unexpected line 1 content '-----BEGIN PRIVATE KEY-----', expected '-----BEGIN CERTIFICATE-----': test", t.getMessage());
        }
    }

    @Test
    public void readOneCertificate() throws Exception {
        @SuppressWarnings("SpellCheckingInspection")
        String data = "\n\n\n\n\n-----BEGIN CERTIFICATE-----\n" +
                "MIIB/jCCAYWgAwIBAgIIdJclisc/elQwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMC\n" +
                "VVMxFDASBgNVBAoMC0FmZmlybVRydXN0MSAwHgYDVQQDDBdBZmZpcm1UcnVzdCBQ\n" +
                "cmVtaXVtIEVDQzAeFw0xMDAxMjkxNDIwMjRaFw00MDEyMzExNDIwMjRaMEUxCzAJ\n" +
                "\t\t\t\t\n" +
                "BgNVBAYTAlVTMRQwEgYDVQQKDAtBZmZpcm1UcnVzdDEgMB4GA1UEAwwXQWZmaXJt\n" +
                "VHJ1c3QgUHJlbWl1bSBFQ0MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQNMF4bFZ0D\n" +
                "0KF5Nbc6PJJ6yhUczWLznCZcBz3lVPqj1swS6vQUX+iOGasvLkjmrBhDeKzQN8O9\n" +
                "ss0s5kfiGuZjuD0uL3jET9v0D6RoTFVya5UdThhClXjMNzyR4ptlKymjQjBAMB0G\n" +
                "A1UdDgQWBBSaryl6wBE1NSZRMADDav5A1a7WPDAPBgNVHRMBAf8EBTADAQH/MA4G\n" +
                "A1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNnADBkAjAXCfOHiFBar8jAQr9HX/Vs\n" +
                "aobgxCd05DhT1wV/GzTjxi+zygk8N53X57hG8f2h4nECMEJZh0PUUd+60wkyWs6I\n" +
                "flc9nF9Ca/UHLbXwgpP5WW+uZPpY5Yse42O+tYHNbwKMeQ==\n" +
                "-----END CERTIFICATE-----";

        List<X509Certificate> result = PemReaderUtil.readPemBundle(new ByteArrayInputStream(data.getBytes(StandardCharsets.US_ASCII)), "test");
        Assert.assertEquals(1, result.size());

        Assert.assertEquals("C=US,O=AffirmTrust,CN=AffirmTrust Premium ECC", result.get(0).getSubjectDN().toString());

        // same as openssl x509 -noout -fingerprint -sha256 -inform pem -in my.pem
        Assert.assertEquals("bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423", sha256hex(result.get(0).getEncoded()));
    }

    @Test
    public void readCertificateBundle() throws Exception {
        List<X509Certificate> result;

        try (InputStream stream = getClass().getResourceAsStream("/ca-certificates.crt")) {
            result = PemReaderUtil.readPemBundle(Objects.requireNonNull(stream), "test");
        }

        Assert.assertEquals(128, result.size());
    }
}
