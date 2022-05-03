package org.jetbrains.nativecerts.linux;

import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class PemReaderUtil {
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";

    public static List<X509Certificate> readPemBundle(@NotNull InputStream inputStream, @NotNull String moniker) throws IOException, CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> result = new ArrayList<>();

        try (LineNumberReader reader = new LineNumberReader(new InputStreamReader(inputStream, StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String outerTrimmed = line.trim();
                if (outerTrimmed.isEmpty()) {
                    continue;
                }

                if (outerTrimmed.equals(BEGIN_CERT)) {
                    StringBuilder base64encoded = new StringBuilder();
                    while (true) {
                        line = reader.readLine();
                        if (line == null) {
                            throw new IllegalStateException("Non-closed '" + BEGIN_CERT + "' block at line " +
                                    reader.getLineNumber() +
                                    " : " + moniker);
                        }

                        String innerTrimmed = line.trim();
                        if (innerTrimmed.isEmpty()) {
                            continue;
                        }

                        if (innerTrimmed.equals(END_CERT)) {
                            break;
                        }

                        base64encoded.append(line.trim());
                    }

                    byte[] derEncoding = Base64.getDecoder().decode(base64encoded.toString());
                    X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                            new ByteArrayInputStream(derEncoding)
                    );
                    result.add(certificate);
                }

                // skip all non-certificate lines
            }
        }

        return Collections.unmodifiableList(result);
    }
}
