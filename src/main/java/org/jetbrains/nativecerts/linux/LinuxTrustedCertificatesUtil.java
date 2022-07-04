package org.jetbrains.nativecerts.linux;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.nativecerts.win32.Crypt32ExtUtil;

import java.io.InputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;

public class LinuxTrustedCertificatesUtil {
    private final static Logger LOGGER = Logger.getLogger(Crypt32ExtUtil.class.getName());

    // The same discovery logic as in Go
    // https://github.com/golang/go/blob/0668e3cb1a8407547f1b4e316748d3b898564f8e/src/crypto/x509/root_linux.go

    private static final List<String> possibleFiles = List.of(
            "/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
            "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
            "/etc/ssl/ca-bundle.pem",                            // OpenSUSE
            "/etc/pki/tls/cacert.pem",                           // OpenELEC
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
            "/etc/ssl/cert.pem"                                  // Alpine Linux
    );

    private static final List<String> possibleDirectories = List.of(
            "/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
            "/etc/pki/tls/certs",           // Fedora/RHEL
            "/system/etc/security/cacerts"  // Android
    );

    public static Collection<X509Certificate> getSystemCertificates() {
        Set<X509Certificate> result = new HashSet<>();

        for (String file : possibleFiles) {
            result.addAll(tryReadFromFile(Path.of(file)));
        }

        for (String dir : possibleDirectories) {
            result.addAll(tryReadFromDirectory(Path.of(dir)));
        }

        if (LOGGER.isLoggable(Level.FINE)) {
            StringBuilder message = new StringBuilder();
            message.append(result.size()).append(" certificates were read from various system locations");
            for (X509Certificate certificate : result) {
                message.append("\n  ").append(certificate.getSubjectDN());
            }
            LOGGER.fine(message.toString());
        }

        return result;
    }

    private static Set<X509Certificate> tryReadFromDirectory(@NotNull Path dir) {
        if (!Files.isDirectory(dir)) {
            LOGGER.fine("Not reading certificates from " + dir + ": not a directory");
            return Collections.emptySet();
        }

        LOGGER.fine("Reading certificates from " + dir + ": file does not exist");
        try (Stream<Path> filesStream = Files.list(dir)) {
            List<Path> paths = filesStream.collect(Collectors.toList());

            Set<X509Certificate> result = new HashSet<>();
            for (Path path : paths) {
                if (Files.isRegularFile(path)) {
                    result.addAll(tryReadFromFile(path));
                }
            }
            return result;
        } catch (Throwable t) {
            LOGGER.warning(renderExceptionMessage("Unable to read certificates from directory " + dir, t));
            return Collections.emptySet();
        }
    }

    private static List<X509Certificate> tryReadFromFile(@NotNull Path file) {
        try {
            if (!Files.exists(file)) {
                LOGGER.fine("Not reading certificates from " + file + ": file does not exist");
                return Collections.emptyList();
            }

            if (!Files.isRegularFile(file)) {
                LOGGER.warning("Not reading certificates from " + file + ": not a regular file");
                return Collections.emptyList();
            }

            try (InputStream stream = Files.newInputStream(file)) {
                List<X509Certificate> list = PemReaderUtil.readPemBundle(stream, file.toString());

                if (LOGGER.isLoggable(Level.FINE)) {
                    StringBuilder message = new StringBuilder();
                    message.append("Received ").append(list.size()).append(" certificates from ").append(file);

                    for (X509Certificate certificate : list) {
                        message.append("\n  ").append(certificate.getSubjectDN());
                    }

                    LOGGER.fine(message.toString());
                }

                return list;
            }
        } catch (AccessDeniedException t) {
            LOGGER.warning("Not reading certificates from " + file + ": access denied");
            return Collections.emptyList();
        } catch (Throwable t) {
            LOGGER.warning(renderExceptionMessage("Unable to read certificates from " + file, t));
            return Collections.emptyList();
        }
    }
}
