package org.jetbrains.nativecerts;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class NativeCertsTestUtil {
    public static boolean isManualTestingEnabled = toBooleanChecked(System.getProperty("manual.test", "false"));

    private static boolean toBooleanChecked(String value) {
        switch (value) {
            case "true":
                return true;
            case "false":
                return false;
            default:
                throw new IllegalArgumentException("Illegal boolean string, use only 'true' or 'false': " + value);
        }
    }

    public static Path getTestCertificatePath() {
        String fileName = "/certificates-tests.labs.intellij.net.cer";
        try {
            Path path = Path.of(Objects.requireNonNull(NativeCertsTestUtil.class.getResource(fileName)).toURI());
            if (!Files.isRegularFile(path)) {
                throw new IllegalStateException("Path not found: " + path);
            }
            return path;
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate getTestCertificate() {
        try {
            byte[] bytes = Files.readAllBytes(getTestCertificatePath());
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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

    public static void executeProcess(List<String> command) {
        int rc = executeProcessAndGetExitCode(command);
        if (rc != 0) {
            throw new IllegalStateException("Process [" + String.join(" ", command) + "] exited with exit code " + rc);
        }
    }

    public static int executeProcessAndGetExitCode(List<String> command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.inheritIO();
            pb.directory(new File(System.getProperty("user.home")));
            Process process = pb.start();
            if (!process.waitFor(10, TimeUnit.MINUTES)) {
                process.destroyForcibly();
                throw new IllegalStateException("Timeout waiting for process " + String.join(" ", command));
            }
            return process.exitValue();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public enum ExitCodeHandling {
        ASSERT,
        IGNORE,
    }

    public static String executeProcessGetStdout(ExitCodeHandling exitCodeHandling, String... command) {
        try {
            Path out = Files.createTempFile("process-stdout-", ".txt");
            try {
                ProcessBuilder pb = new ProcessBuilder(command);
                pb.inheritIO();
                pb.redirectInput(ProcessBuilder.Redirect.INHERIT);
                pb.redirectError(ProcessBuilder.Redirect.INHERIT);
                pb.redirectOutput(out.toFile());
                pb.directory(new File(System.getProperty("user.home")));
                Process process = pb.start();
                if (!process.waitFor(10, TimeUnit.MINUTES)) {
                    process.destroyForcibly();
                    throw new IllegalStateException("Timeout waiting for process " + String.join(" ", command));
                }

                int rc = process.exitValue();
                if (rc != 0 && exitCodeHandling == ExitCodeHandling.ASSERT) {
                    throw new IllegalStateException("Process [" + String.join(" ", command) + "] exited with exit code " + rc);
                }

                return Files.readString(out);
            } finally {
                Files.deleteIfExists(out);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SafeVarargs
    public static <T> List<T> combineLists(List<T>... lists) {
        List<T> result = new ArrayList<>();
        for (List<T> list : lists) {
            result.addAll(list);
        }
        return result;
    }
}
