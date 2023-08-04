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
import java.util.logging.Level;
import java.util.logging.Logger;

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
            // Try to parse with a standard provider (usually the provider bundled with JRE)
            return parseCertificate(bytes, CertificateFactory.getInstance("X.509"));
        } catch (Throwable e) {
            Logger logger = Logger.getLogger(NativeTrustedRootsInternalUtils.class.getName());

            if (logger.isLoggable(Level.FINE)) {
                logger.fine(renderExceptionMessage("Unable to parse certificate with a standard X509 parser, falling back to BouncyCastle", e));
            }

            // If it fails, fallback to explicitly specified BouncyCastle provider
            // see, e.g., https://youtrack.jetbrains.com/issue/IDEA-318004

            CertificateFactory bcProvider;
            try {
                bcProvider = CertificateFactory.getInstance("X.509", BouncyCastleLazyProvider.INSTANCE);
            } catch (CertificateException ex) {
                throw new RuntimeException(ex);
            }

            return parseCertificate(bytes, bcProvider);
        }
    }

    static X509Certificate parseCertificate(byte[] bytes, CertificateFactory cf) {
        try {
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));

            // force parsing of the certificate to mitigate errors like
            // IDE fails to connect to network due to "invalid info structure in RSA public key" error in my corporate network
            // https://youtrack.jetbrains.com/issue/IDEA-327220
            certificate.getPublicKey();

            return certificate;
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static class BouncyCastleLazyProvider {
        public static BouncyCastleProvider INSTANCE = new BouncyCastleProvider();
    }
}
