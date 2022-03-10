package org.jetbrains.nativecerts.win32;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.*;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.sun.jna.platform.win32.WinError.*;

public class Crypt32ExtUtil {
    public static void CertCloseStore(WinCrypt.HCERTSTORE handle) {
        if (!Crypt32.INSTANCE.CertCloseStore(handle, 0)) {
            throw new IllegalStateException("CertCloseStore: " + Kernel32Util.formatMessage(Native.getLastError()));
        }

        {
            int a = 4;
        }
    }

    public static List<X509Certificate> GatherEnterpriseCertsForLocation(int location, String store_name) throws CertificateException {
        if (!(location == Crypt32Ext.CERT_SYSTEM_STORE_LOCAL_MACHINE ||
                location == Crypt32Ext.CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY ||
                location == Crypt32Ext.CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE ||
                location == Crypt32Ext.CERT_SYSTEM_STORE_CURRENT_USER ||
                location == Crypt32Ext.CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY)) {
            return Collections.emptyList();
        }

        int flags = location | Crypt32Ext.CERT_STORE_OPEN_EXISTING_FLAG | Crypt32Ext.CERT_STORE_READONLY_FLAG;

        WinCrypt.HCERTSTORE hcertstore =
                Crypt32Ext.INSTANCE.CertOpenStore(
                        new WTypes.LPSTR(new Pointer(Crypt32Ext.CERT_STORE_PROV_SYSTEM_REGISTRY_W)),
                        0,
                        new WinCrypt.HCRYPTPROV_LEGACY(0),
                        flags,
                        new WTypes.LPWSTR(store_name).getPointer());
        if (hcertstore == null) {
            int errorCode = Native.getLastError();

            if (errorCode == ERROR_NO_MORE_FILES) {
                return Collections.emptyList();
            } else {
                throw new Win32Exception(errorCode);
            }
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

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

                X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
                result.add(x509);

                prev = certificate;
            }

            return result;
        } finally {
            CertCloseStore(hcertstore);
        }
    }
}
