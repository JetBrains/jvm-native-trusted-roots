package org.jetbrains.nativecerts.mac;

import org.jetbrains.nativecerts.NativeLibrary;

import java.lang.foreign.MemorySegment;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

final class SecurityFramework {
    static final int SUCCESS = 0;
    static final int ITEM_NOT_FOUND = -25300;
    static final int USER = 0;
    static final int ADMIN = 1;
    static final long TRUST_ROOT = 1;
    private static final NativeLibrary LIBRARY = new NativeLibrary("/System/Library/Frameworks/Security.framework/Security");
    static final NativeLibrary.Function ITEM_COPY_MATCHING = LIBRARY.function("SecItemCopyMatching", of(JAVA_INT, ADDRESS, ADDRESS));
    static final NativeLibrary.Function KEYCHAIN_OPEN = LIBRARY.function("SecKeychainOpen", of(JAVA_INT, ADDRESS, ADDRESS));
    static final NativeLibrary.Function CERTIFICATE_COPY_DATA = LIBRARY.function("SecCertificateCopyData", of(ADDRESS, ADDRESS));
    static final NativeLibrary.Function POLICY_CREATE_SSL = LIBRARY.function("SecPolicyCreateSSL", of(ADDRESS, JAVA_BYTE, ADDRESS));
    static final NativeLibrary.Function POLICY_COPY_PROPERTIES = LIBRARY.function("SecPolicyCopyProperties", of(ADDRESS, ADDRESS));
    static final NativeLibrary.Function TRUST_CREATE = LIBRARY.function("SecTrustCreateWithCertificates",
            of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
    static final NativeLibrary.Function TRUST_EVALUATE = LIBRARY.function("SecTrustEvaluateWithError", of(JAVA_BYTE, ADDRESS, ADDRESS));
    static final NativeLibrary.Function COPY_TRUST_SETTINGS = LIBRARY.function("SecTrustSettingsCopyTrustSettings",
            of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
    private static final NativeLibrary.Function ERROR_MESSAGE = LIBRARY.function("SecCopyErrorMessageString", of(ADDRESS, JAVA_INT, ADDRESS));
    static final long CERTIFICATE_TYPE = (long) LIBRARY.function("SecCertificateGetTypeID", of(JAVA_LONG)).invoke();
    static final long POLICY_TYPE = (long) LIBRARY.function("SecPolicyGetTypeID", of(JAVA_LONG)).invoke();

    static final MemorySegment CLASS = constant("kSecClass");
    static final MemorySegment CLASS_CERTIFICATE = constant("kSecClassCertificate");
    static final MemorySegment MATCH_LIMIT = constant("kSecMatchLimit");
    static final MemorySegment MATCH_LIMIT_ALL = constant("kSecMatchLimitAll");
    static final MemorySegment MATCH_SEARCH_LIST = constant("kSecMatchSearchList");
    static final MemorySegment RETURN_REF = constant("kSecReturnRef");
    static final MemorySegment POLICY_APPLE_SSL = constant("kSecPolicyAppleSSL");
    static final MemorySegment POLICY_OID = constant("kSecPolicyOid");
    static final MemorySegment TRUST_SETTINGS_RESULT = CoreFoundationExt.createString("kSecTrustSettingsResult");
    static final MemorySegment TRUST_SETTINGS_ALLOWED_ERROR = CoreFoundationExt.createString("kSecTrustSettingsAllowedError");
    static final MemorySegment TRUST_SETTINGS_POLICY_NAME = CoreFoundationExt.createString("kSecTrustSettingsPolicyName");
    static final MemorySegment TRUST_SETTINGS_POLICY = CoreFoundationExt.createString("kSecTrustSettingsPolicy");

    private static MemorySegment constant(String name) {
        return CoreFoundationExt.requireNonNull(LIBRARY.symbol(name).reinterpret(ADDRESS.byteSize()).get(ADDRESS, 0));
    }

    static CoreFoundationExt.Error error(int status) {
        var message = (MemorySegment) ERROR_MESSAGE.invoke(status, NULL);
        try {
            return new CoreFoundationExt.Error("NSOSStatusErrorDomain", status,
                    message.equals(NULL) ? "OSStatus: " + status : CoreFoundationExt.stringValue(message));
        } finally {
            CoreFoundationExt.release(message);
        }
    }

    static void checkStatus(String operation, int status) {
        if (status != SUCCESS) {
            throw new IllegalStateException(operation + " failed: " + error(status));
        }
    }

    private SecurityFramework() {
    }
}
