package org.jetbrains.nativecerts.win32;

import org.jetbrains.nativecerts.NativeLibrary;

import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.FunctionDescriptor.ofVoid;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

final class Crypt32Ext {
    static final int CERT_STORE_PROV_SYSTEM_REGISTRY_W = 13;
    static final int CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
    static final int CERT_STORE_READONLY_FLAG = 0x00008000;
    static final int CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
    static final int CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;
    static final int CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = 0x00070000;
    static final int CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = 0x00080000;
    static final int CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = 0x00090000;
    static final int CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY = 0x80000000;
    static final int CERT_CHAIN_POLICY_SSL = 4;
    static final int X509_ASN_ENCODING = 1;
    static final int PKCS_7_ASN_ENCODING = 0x00010000;
    static final int ERROR_FILE_NOT_FOUND = 2;
    static final int ERROR_NO_MORE_FILES = 18;
    static final int CRYPT_E_NOT_FOUND = 0x80092004;

    static final MemoryLayout CALL_STATE = Linker.Option.captureStateLayout();
    private static final long LAST_ERROR = WinCryptStructures.offset(CALL_STATE, "GetLastError");
    private static final Linker.Option CAPTURE_LAST_ERROR = Linker.Option.captureCallState("GetLastError");
    private static final NativeLibrary LIBRARY = new NativeLibrary("Crypt32.dll");

    static final NativeLibrary.Function OPEN_STORE = LIBRARY.function("CertOpenStore",
            of(ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS), CAPTURE_LAST_ERROR);
    static final NativeLibrary.Function ENUM_CERTIFICATES = LIBRARY.function("CertEnumCertificatesInStore",
            of(ADDRESS, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
    static final NativeLibrary.Function CLOSE_STORE = LIBRARY.function("CertCloseStore",
            of(JAVA_INT, ADDRESS, JAVA_INT), CAPTURE_LAST_ERROR);
    static final NativeLibrary.Function CREATE_CONTEXT = LIBRARY.function("CertCreateCertificateContext",
            of(ADDRESS, JAVA_INT, ADDRESS, JAVA_INT), CAPTURE_LAST_ERROR);
    static final NativeLibrary.Function FREE_CONTEXT = LIBRARY.function("CertFreeCertificateContext", of(JAVA_INT, ADDRESS));
    static final NativeLibrary.Function GET_CHAIN = LIBRARY.function("CertGetCertificateChain",
            of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
    static final NativeLibrary.Function VERIFY_CHAIN_POLICY = LIBRARY.function("CertVerifyCertificateChainPolicy",
            of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
    static final NativeLibrary.Function FREE_CHAIN = LIBRARY.function("CertFreeCertificateChain", ofVoid(ADDRESS));

    static int lastError(MemorySegment state) {
        return state.get(JAVA_INT, LAST_ERROR);
    }

    static WindowsCertificateException failure(NativeLibrary.Function function, MemorySegment state) {
        return new WindowsCertificateException(function.name(), lastError(state));
    }

    private Crypt32Ext() {
    }
}
