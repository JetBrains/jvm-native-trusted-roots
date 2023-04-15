package org.jetbrains.nativecerts;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;

@ApiStatus.Internal
public class NativeTrustedRootsInternalUtils {
    private static final String _OS_NAME = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
    public static final boolean isWindows = _OS_NAME.startsWith("windows");
    public static final boolean isMac = _OS_NAME.startsWith("mac");
    public static final boolean isLinux = _OS_NAME.startsWith("linux");

    public static String renderExceptionMessage(@NotNull String message, @NotNull Throwable exception) {
        StringWriter throwableText = new StringWriter();
        exception.printStackTrace(new PrintWriter(throwableText));
        return message + ": " + exception.getMessage() + "\n" + throwableText;
    }

    public static String sha256hex(final byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(bytes);
            return toHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String sha1hex(final byte[] bytes) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-1");
            final byte[] hash = digest.digest(bytes);
            return toHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String toHex(byte[] bytes) {
        final StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            final String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static X509Certificate parseCertificate(byte[] bytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleLazyProvider.INSTANCE);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static class BouncyCastleLazyProvider {
        public static BouncyCastleProvider INSTANCE = new BouncyCastleProvider();
    }
}
