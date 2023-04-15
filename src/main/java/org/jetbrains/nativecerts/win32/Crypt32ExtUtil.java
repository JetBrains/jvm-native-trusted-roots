package org.jetbrains.nativecerts.win32;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.WTypes;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinCrypt;
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
            List<X509Certificate> list = gatherEnterpriseCertsForLocation(entry.getValue(), "ROOT");

            if (LOGGER.isLoggable(Level.FINE)) {
                StringBuilder message = new StringBuilder();
                message.append("Received ").append(list.size()).append(" certificates from store ROOT / ").append(entry.getKey());

                for (X509Certificate certificate : list) {
                    message.append("\n  ROOT/").append(entry.getKey()).append(": ").append(certificate.getSubjectDN());
                }

                LOGGER.fine(message.toString());
            }

            result.addAll(list);
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
}
