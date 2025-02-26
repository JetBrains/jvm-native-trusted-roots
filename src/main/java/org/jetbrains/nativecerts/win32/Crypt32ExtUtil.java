package org.jetbrains.nativecerts.win32;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.WTypes;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.ptr.PointerByReference;
import org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.sun.jna.platform.win32.WinError.CRYPT_E_NOT_FOUND;
import static com.sun.jna.platform.win32.WinError.ERROR_FILE_NOT_FOUND;
import static com.sun.jna.platform.win32.WinError.ERROR_NO_MORE_FILES;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.renderExceptionMessage;

public class Crypt32ExtUtil {
    private final static Logger LOGGER = Logger.getLogger(Crypt32ExtUtil.class.getName());

    private static final Map<String, Integer> customTrustedCertificatesLocations = Map.of(
            "CERT_SYSTEM_STORE_LOCAL_MACHINE", Crypt32Ext.CERT_SYSTEM_STORE_LOCAL_MACHINE,
            "CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY", Crypt32Ext.CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
            "CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE", Crypt32Ext.CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
            "CERT_SYSTEM_STORE_CURRENT_USER", Crypt32Ext.CERT_SYSTEM_STORE_CURRENT_USER,
            "CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY", Crypt32Ext.CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY
    );

    public static Collection<X509Certificate> getCustomTrustedRootCertificates() {
        HashSet<X509Certificate> result = new HashSet<>();

        for (Map.Entry<String, Integer> entry : customTrustedCertificatesLocations.entrySet()) {
            List<X509Certificate> root = gatherEnterpriseCertsForLocation(entry.getValue(), "ROOT");
            List<X509Certificate> intermediates = gatherEnterpriseCertsForLocation(entry.getValue(), "CA");

            if (LOGGER.isLoggable(Level.FINE)) {
                StringBuilder message = new StringBuilder();

                message.append("Received ").append(root.size()).append(" certificates from store ROOT / ").append(entry.getKey());
                for (X509Certificate certificate : root) {
                    message.append("\n  ROOT/").append(entry.getKey()).append(": ").append(certificate.getSubjectX500Principal());
                }

                message.append("\nReceived ").append(intermediates.size()).append(" certificates from store CA (Intermediates) / ").append(entry.getKey());
                for (X509Certificate certificate : intermediates) {
                    message.append("\n  CA/").append(entry.getKey()).append(": ").append(certificate.getSubjectX500Principal());
                }

                LOGGER.fine(message.toString());
            }

            result.addAll(root);

            for (X509Certificate intermediate : intermediates) {
                try {
                    validateCertificate(intermediate.getEncoded());
                    result.add(intermediate);
                } catch (Throwable t) {
                    LOGGER.log(
                            Level.FINE,
                            "Unable to validate whether certificate '" + intermediate.getSubjectX500Principal() + "' is trusted: " + t.getMessage(),
                            t);
                }
            }
        }

        return result;
    }

    public static void CertCloseStore(WinCrypt.HCERTSTORE handle) {
        if (!Crypt32.INSTANCE.CertCloseStore(handle, 0)) {
            throw new IllegalStateException("CertCloseStore: " + Kernel32Util.formatMessage(Native.getLastError()));
        }
    }

    public static List<X509Certificate> gatherEnterpriseCertsForLocation(int location, String store_name) {
        int flags = location | Crypt32Ext.CERT_STORE_OPEN_EXISTING_FLAG | Crypt32Ext.CERT_STORE_READONLY_FLAG;

        WinCrypt.HCERTSTORE hcertstore =
                Crypt32Ext.INSTANCE.CertOpenStore(
                        new WTypes.LPSTR(new Pointer(Crypt32Ext.CERT_STORE_PROV_SYSTEM_REGISTRY_W)),
                        0,
                        new WinCrypt.HCRYPTPROV_LEGACY(0),
                        flags,
                        new WTypes.LPWSTR(store_name));
        if (hcertstore == null) {
            int errorCode = Native.getLastError();

            if (errorCode == ERROR_NO_MORE_FILES || errorCode == ERROR_FILE_NOT_FOUND) {
                return Collections.emptyList();
            } else {
                throw new Win32Exception(errorCode);
            }
        }

        try {
            List<X509Certificate> result = new ArrayList<>();

            WinCrypt.CERT_CONTEXT.ByReference prev = null;
            while (true) {
                WinCrypt.CERT_CONTEXT.ByReference certificate =
                        Crypt32.INSTANCE.CertEnumCertificatesInStore(
                                hcertstore, prev == null ? null : prev.getPointer());
                if (certificate == null) {
                    int errorCode = Native.getLastError();
                    if (errorCode != CRYPT_E_NOT_FOUND && errorCode != ERROR_NO_MORE_FILES) {
                        throw new Win32Exception(errorCode);
                    }

                    break;
                }

                byte[] bytes = certificate.pbCertEncoded.getByteArray(0, certificate.cbCertEncoded);

                try {
                    X509Certificate x509 = NativeTrustedRootsInternalUtils.parseCertificate(bytes);
                    result.add(x509);
                } catch (Throwable parsingException) {
                    LOGGER.warning(renderExceptionMessage(
                            "Unable to parse one of the certificates" +
                                    "from store '" + store_name + "'",
                            parsingException));
                }

                prev = certificate;
            }

            return result;
        } finally {
            CertCloseStore(hcertstore);
        }
    }

    public static void validateCertificate(byte[] encodedCertificate) {
        var certificateContext = Crypt32Ext.INSTANCE.CertCreateCertificateContext(
                WinCrypt.X509_ASN_ENCODING | WinCrypt.PKCS_7_ASN_ENCODING, encodedCertificate, encodedCertificate.length);
        if (certificateContext == null) {
            throw new Win32Exception(Native.getLastError());
        }

        try {
            WinCrypt.CERT_CHAIN_PARA pChainPara = new WinCrypt.CERT_CHAIN_PARA();
            pChainPara.cbSize = pChainPara.size();
            pChainPara.RequestedUsage.dwType = WinCrypt.USAGE_MATCH_TYPE_AND;
            pChainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
            pChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = null;

            PointerByReference ppChainContext = new PointerByReference();
            if (!Crypt32.INSTANCE.CertGetCertificateChain(
                    null, certificateContext, null, null, pChainPara,
                    Crypt32Ext.CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
                    null, ppChainContext)) {
                throw new Win32Exception(Native.getLastError());
            }

            if (ppChainContext.getValue() == null) {
                throw new IllegalStateException("CertGetCertificateChain was successful, but returned chain context is null");
            }

            WinCrypt.CERT_CHAIN_CONTEXT pChainContext = Structure.newInstance(WinCrypt.CERT_CHAIN_CONTEXT.class, ppChainContext.getValue());
            pChainContext.read();

            if (pChainContext.cbSize != pChainContext.size()) {
                throw new IllegalStateException("CertGetCertificateChain was successful, but returned chain context size is incorrect." +
                        "returned cbSize is " + pChainContext.cbSize + ", but the structure size is " + pChainContext.size());
            }

            try {
                WinCrypt.CERT_CHAIN_POLICY_PARA chainPolicyPara = new WinCrypt.CERT_CHAIN_POLICY_PARA();
                chainPolicyPara.cbSize = chainPolicyPara.size();
                chainPolicyPara.dwFlags = 0;

                WinCrypt.CERT_CHAIN_POLICY_STATUS policyStatus = new WinCrypt.CERT_CHAIN_POLICY_STATUS();
                policyStatus.dwError = 1; // extra check that CertVerifyCertificateChainPolicy actually sets this field
                policyStatus.cbSize = policyStatus.size();

                if (!Crypt32.INSTANCE.CertVerifyCertificateChainPolicy(
                        new WTypes.LPSTR(Pointer.createConstant(Crypt32Ext.CERT_CHAIN_POLICY_SSL)),
                        pChainContext, chainPolicyPara, policyStatus)) {
                    throw new Win32Exception(Native.getLastError());
                }

                int dwError = policyStatus.dwError;
                if (dwError != 0) {
                    throw new Win32Exception(dwError, null, "CertVerifyCertificateChainPolicy failed to validate certificate with code " +
                            Integer.toHexString(dwError) + ":\n" + Kernel32Util.formatMessage(dwError)) {
                    };
                }
            } finally {
                Crypt32.INSTANCE.CertFreeCertificateChain(pChainContext);
            }
        } finally {
            Crypt32.INSTANCE.CertFreeCertificateContext(certificateContext);
        }
    }
}
