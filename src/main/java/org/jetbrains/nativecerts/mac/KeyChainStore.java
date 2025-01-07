package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class KeyChainStore {

    public static List<X509Certificate> getPredefinedRootCertificates() {
        return getAppleKeyChainStore("KeychainStore-ROOT");
    }

    public static List<X509Certificate> getCustomTrustedCertificates() {
        return getAppleKeyChainStore("KeychainStore");
    }

    public static Collection<X509Certificate> getAllTrustedCertificates() {
        List<X509Certificate> customTrustedCertificates = getCustomTrustedCertificates();
        List<X509Certificate> osPredefinedCertificates = getPredefinedRootCertificates();

        Set<X509Certificate> result = new HashSet<>(customTrustedCertificates);
        result.addAll(osPredefinedCertificates);

        return result;
    }

    private static @NotNull List<X509Certificate> getAppleKeyChainStore(String keyChainStore) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyChainStore, "Apple");
            keyStore.load(null, null);

            Iterator<String> iterator = keyStore.aliases().asIterator();
            return StreamSupport.stream(Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED), false)
                    .sorted()
                    .map(alias -> {
                        try {
                            return (X509Certificate) keyStore.getCertificate(alias);
                        } catch (KeyStoreException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .collect(Collectors.toList());
        } catch (KeyStoreException e) {
            // only available from Java 23
            if (e.getMessage().equals("KeychainStore-ROOT not found")) {
                return Collections.emptyList();
            }
            throw new RuntimeException(e);
        } catch (NoSuchProviderException | IOException | NoSuchAlgorithmException |
                 CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    static boolean isSelfSignedCertificate(X509Certificate certificate) {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }

        try {
            certificate.verify(certificate.getPublicKey());
        } catch (Exception e) {
            return false;
        }

        return true;
    }
}
