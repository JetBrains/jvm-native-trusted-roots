package org.jetbrains.nativecerts;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.sha256hex;

public class NativeTrustedRootsDebugMain {
    private final static Logger rootLogger = Logger.getLogger("");
    private final static Logger LOG = Logger.getLogger(NativeTrustedRootsDebugMain.class.getName());

    public static void main(String[] args) throws Exception {
        File logFile = File.createTempFile("nativecerts-", ".log");
        setupLogging(logFile);

        Collection<X509Certificate> trustedCertificates = NativeTrustedCertificates.getCustomOsSpecificTrustedCertificates();

        StringBuilder message = new StringBuilder("getCustomOsSpecificTrustedCertificates returned the following certificates (" + trustedCertificates.size() + " pcs):\n");
        int index = 1;
        for (X509Certificate certificate : trustedCertificates) {
            message.append("  ").append(index).append(" / ").append(trustedCertificates.size()).append(". ")
                    .append(certificate.getSubjectDN()).append(" ").append(sha256hex(certificate.getEncoded()));
            index++;
        }

        LOG.info(message.toString());

        //noinspection UseOfSystemOutOrSystemErr
        System.out.println("\nLog file was saved at " + logFile);
    }

    private static void setupLogging(File logFile) throws IOException {
        LogManager.getLogManager().reset();

        SimpleFormatter formatter = new SimpleFormatter();

        final ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.FINEST);
        consoleHandler.setFormatter(formatter);

        final StreamHandler fileHandler = new StreamHandler(new FileOutputStream(logFile), formatter);
        fileHandler.setLevel(Level.FINEST);

        rootLogger.setLevel(Level.FINEST);
        rootLogger.addHandler(consoleHandler);
        rootLogger.addHandler(fileHandler);
    }
}
