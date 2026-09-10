package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeLibrary;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static org.jetbrains.nativecerts.mac.CoreFoundationExtUtil.createString;
import static org.jetbrains.nativecerts.mac.CoreFoundationExtUtil.release;
import static org.jetbrains.nativecerts.mac.CoreFoundationExtUtil.requireNonNull;
import static org.jetbrains.nativecerts.mac.CoreFoundationExtUtil.stringValue;

/**
 * Raw bindings to the parts of the Security framework used by {@link SecurityFrameworkUtil}.
 * <p>
 * Naming and grouping follow the C headers ({@code SecItem.h}, {@code SecPolicy.h}, {@code SecTrustSettings.h},
 * {@code SecBase.h}) so that every identifier can be looked up in Apple documentation as is.
 * All {@code *Ref} types are opaque pointers ({@link MemorySegment}); {@code OSStatus} is {@code int};
 * {@code SecTrustSettingsDomain} is {@code int}; {@code SecTrustSettingsResult} is read out of a CFNumber as {@code long}.
 * Memory ownership follows the Core Foundation Create/Get rules, see {@link CoreFoundationExt}.
 */
@SuppressWarnings({"unused", "SpellCheckingInspection"})
final class SecurityFramework {
    static final String SECURITY_FRAMEWORK_LIBRARY_PATH = "/System/Library/Frameworks/Security.framework/Security";

    private static final NativeLibrary LIBRARY = new NativeLibrary(SECURITY_FRAMEWORK_LIBRARY_PATH);

    private SecurityFramework() {
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Keychain item query keys (SecItem.h). Exported CFStringRef globals, resolved at class initialization.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * A dictionary key whose value is the item’s class.
     *
     * @see <a href="https://developer.apple.com/documentation/security/ksecclass">developer.apple.com</a>
     */
    static final MemorySegment kSecClass = resolveStringConstant("kSecClass");

    /**
     * The value that indicates a certificate item.
     *
     * @see <a href="https://developer.apple.com/documentation/security/kSecClassCertificate">developer.apple.com</a>
     */
    static final MemorySegment kSecClassCertificate = resolveStringConstant("kSecClassCertificate");

    /**
     * A key whose value indicates the match limit.
     *
     * @see <a href="https://developer.apple.com/documentation/security/kSecMatchLimit">developer.apple.com</a>
     */
    static final MemorySegment kSecMatchLimit = resolveStringConstant("kSecMatchLimit");

    /**
     * A value that corresponds to matching an unlimited number of items.
     *
     * @see <a href="https://developer.apple.com/documentation/security/kSecMatchLimitAll">developer.apple.com</a>
     */
    static final MemorySegment kSecMatchLimitAll = resolveStringConstant("kSecMatchLimitAll");

    /**
     * A key whose value indicates a list of items (keychains) to search.
     *
     * @see <a href="https://developer.apple.com/documentation/security/kSecMatchSearchList">developer.apple.com</a>
     */
    static final MemorySegment kSecMatchSearchList = resolveStringConstant("kSecMatchSearchList");

    /**
     * A key whose value is a Boolean indicating whether or not to return a reference to an item.
     *
     * @see <a href="https://developer.apple.com/documentation/security/kSecReturnRef">developer.apple.com</a>
     */
    static final MemorySegment kSecReturnRef = resolveStringConstant("kSecReturnRef");

    // ---------------------------------------------------------------------------------------------------------------
    // Policy keys (SecPolicy.h)
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Basic X509 plus host name verification per RFC 2818. Policy OID value of the SSL policy.
     *
     * @see <a href="https://developer.apple.com/documentation/security/ksecpolicyapplessl">developer.apple.com</a>
     */
    static final MemorySegment kSecPolicyAppleSSL = resolveStringConstant("kSecPolicyAppleSSL");

    /**
     * The object identifier that defines the policy type (CFStringRef). All policies have a value for this key.
     *
     * @see <a href="https://developer.apple.com/documentation/security/ksecpolicyoid">developer.apple.com</a>
     */
    static final MemorySegment kSecPolicyOid = resolveStringConstant("kSecPolicyOid");

    // ---------------------------------------------------------------------------------------------------------------
    // Trust settings usage constraints dictionary keys (SecTrustSettings.h).
    // Unlike the keys above these are `#define kSecTrustSettingsResult CFSTR("kSecTrustSettingsResult")` macros,
    // not exported symbols, so the strings are created here with the same text.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * A number indicating the effective trust setting for this usage constraints dictionary.
     * See {@code kSecTrustSettingsResult*} constants below for the possible values.
     *
     * @see <a href="https://developer.apple.com/documentation/security/ksectrustsettingsresult">developer.apple.com</a>
     */
    static final MemorySegment kSecTrustSettingsResult = createString("kSecTrustSettingsResult");

    /**
     * A number which, if encountered during certificate verification, is ignored for that certificate.
     *
     * @see <a href="https://developer.apple.com/documentation/security/ksectrustsettingsallowederror">developer.apple.com</a>
     */
    static final MemorySegment kSecTrustSettingsAllowedError = createString("kSecTrustSettingsAllowedError");

    /**
     * Specifies a cert verification policy, e.g., sslServer, eapClient, etc. using policy names.
     * This entry can be used to restrict the policy where the same Policy Constant is used for multiple policyNames.
     */
    static final MemorySegment kSecTrustSettingsPolicyName = createString("kSecTrustSettingsPolicyName");

    /**
     * A policy object (SecPolicyRef) specifying the certificate verification policy.
     *
     * @see <a href="https://developer.apple.com/documentation/security/ksectrustsettingspolicy">developer.apple.com</a>
     */
    static final MemorySegment kSecTrustSettingsPolicy = createString("kSecTrustSettingsPolicy");

    // ---------------------------------------------------------------------------------------------------------------
    // SecTrustSettingsResult: trust settings returned in usage constraints dictionaries (value of kSecTrustSettingsResult)
    // https://developer.apple.com/documentation/security/sectrustsettingsresult
    // ---------------------------------------------------------------------------------------------------------------

    /** Never valid in a Trust Settings array or in an API call. */
    static final long kSecTrustSettingsResultInvalid = 0;
    /** Root cert is explicitly trusted. */
    static final long kSecTrustSettingsResultTrustRoot = 1;
    /** Non-root cert is explicitly trusted. */
    static final long kSecTrustSettingsResultTrustAsRoot = 2;
    /** Cert is explicitly distrusted. */
    static final long kSecTrustSettingsResultDeny = 3;
    /** Neither trusted nor distrusted; evaluation proceeds as usual. */
    static final long kSecTrustSettingsResultUnspecified = 4;

    // ---------------------------------------------------------------------------------------------------------------
    // SecTrustSettingsDomain: the trust settings domains
    // https://developer.apple.com/documentation/security/sectrustsettingsdomain
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Per-user trust settings.
     *
     * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsdomain/user">developer.apple.com</a>
     */
    static final int kSecTrustSettingsDomainUser = 0;

    /**
     * Locally administered, system-wide trust settings. Administrator privileges are required to make changes to this domain.
     *
     * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsdomain/admin">developer.apple.com</a>
     */
    static final int kSecTrustSettingsDomainAdmin = 1;

    /**
     * System trust settings. These trust settings are immutable and comprise the set of trusted root certificates
     * supplied in macOS. These settings are read-only, even by root.
     *
     * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsdomain/system">developer.apple.com</a>
     */
    static final int kSecTrustSettingsDomainSystem = 2;

    // ---------------------------------------------------------------------------------------------------------------
    // OSStatus: result codes common to many Security framework functions
    // https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
    // ---------------------------------------------------------------------------------------------------------------

    static final int errSecSuccess = 0;

    /**
     * The specified item could not be found in the keychain.
     *
     * @see <a href="https://developer.apple.com/documentation/security/errsecitemnotfound">developer.apple.com</a>
     */
    static final int errSecItemNotFound = -25300;

    /**
     * No Trust Settings were found.
     *
     * @see <a href="https://developer.apple.com/documentation/security/errsecnotrustsettings">developer.apple.com</a>
     */
    static final int errSecNoTrustSettings = -25263;

    // ---------------------------------------------------------------------------------------------------------------
    // CFTypeIDs of Security framework objects, used to verify pointers coming back from the framework
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Type of {@code SecCertificateRef}: an abstract Core Foundation-type object representing an X.509 certificate.
     *
     * @see <a href="https://developer.apple.com/documentation/security/seccertificateref">developer.apple.com</a>
     */
    static final long SEC_CERTIFICATE_TYPE_ID = typeId("SecCertificateGetTypeID");

    /**
     * Type of {@code SecPolicyRef}: an object that represents a trust policy.
     *
     * @see <a href="https://developer.apple.com/documentation/security/secpolicyref">developer.apple.com</a>
     */
    static final long SEC_POLICY_TYPE_ID = typeId("SecPolicyGetTypeID");

    // ---------------------------------------------------------------------------------------------------------------
    // Functions
    // ---------------------------------------------------------------------------------------------------------------

    private static final MethodHandle SecItemCopyMatchingHandle = LIBRARY.downcall("SecItemCopyMatching",
            of(JAVA_INT, ADDRESS, ADDRESS));
    private static final MethodHandle SecKeychainOpenHandle = LIBRARY.downcall("SecKeychainOpen",
            of(JAVA_INT, ADDRESS, ADDRESS));
    private static final MethodHandle SecCertificateCopyDataHandle = LIBRARY.downcall("SecCertificateCopyData",
            of(ADDRESS, ADDRESS));
    private static final MethodHandle SecPolicyCreateSSLHandle = LIBRARY.downcall("SecPolicyCreateSSL",
            of(ADDRESS, JAVA_BYTE, ADDRESS));
    private static final MethodHandle SecPolicyCopyPropertiesHandle = LIBRARY.downcall("SecPolicyCopyProperties",
            of(ADDRESS, ADDRESS));
    private static final MethodHandle SecTrustCreateWithCertificatesHandle = LIBRARY.downcall("SecTrustCreateWithCertificates",
            of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle SecTrustEvaluateWithErrorHandle = LIBRARY.downcall("SecTrustEvaluateWithError",
            of(JAVA_BYTE, ADDRESS, ADDRESS));
    private static final MethodHandle SecTrustSettingsCopyTrustSettingsHandle = LIBRARY.downcall("SecTrustSettingsCopyTrustSettings",
            of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
    private static final MethodHandle SecCopyErrorMessageStringHandle = LIBRARY.downcall("SecCopyErrorMessageString",
            of(ADDRESS, JAVA_INT, ADDRESS));

    /**
     * Returns one or more keychain items that match a search query, or copies attributes of specific keychain items.
     *
     * @param query  A dictionary containing an item class specification ({@link #kSecClass}) and optional attributes
     *               for controlling the search ({@link #kSecMatchLimit}, {@link #kSecMatchSearchList}, {@link #kSecReturnRef}).
     * @param result On return, a pointer to the found items: a CFArrayRef of SecCertificateRef when
     *               {@link #kSecMatchLimitAll} and {@link #kSecReturnRef} are used. Release it with {@code CFRelease}.
     * @return A result code, see {@link #errSecSuccess}. {@link #errSecItemNotFound} if nothing matched.
     * @see <a href="https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)">developer.apple.com</a>
     */
    static int SecItemCopyMatching(@NotNull MemorySegment query, @NotNull MemorySegment result) {
        try {
            return (int) SecItemCopyMatchingHandle.invokeExact(query, result);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecItemCopyMatching", e);
        }
    }

    /**
     * Opens a keychain.
     *
     * @param pathName A constant character string (NUL-terminated C string) representing the POSIX path to the keychain to open.
     * @param keychain On return, a pointer to the keychain object (SecKeychainRef).
     *                 You must call {@code CFRelease} to release this object when you are finished using it.
     * @return A result code, see {@link #errSecSuccess}.
     * @see <a href="https://developer.apple.com/documentation/security/seckeychainopen(_:_:)">developer.apple.com</a>
     */
    static int SecKeychainOpen(@NotNull MemorySegment pathName, @NotNull MemorySegment keychain) {
        try {
            return (int) SecKeychainOpenHandle.invokeExact(pathName, keychain);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecKeychainOpen", e);
        }
    }

    /**
     * Returns a DER representation of a certificate given a certificate object.
     *
     * @param certificate The certificate object (SecCertificateRef) for which you wish to return the
     *                    DER (Distinguished Encoding Rules) representation of the X.509 certificate.
     * @return The DER representation of the certificate (CFDataRef). Call {@code CFRelease} to release this object
     * when you are finished with it. Returns NULL if the data passed in the certificate parameter is not a valid
     * certificate object.
     * @see <a href="https://developer.apple.com/documentation/security/1396080-seccertificatecopydata">developer.apple.com</a>
     */
    static MemorySegment SecCertificateCopyData(@NotNull MemorySegment certificate) {
        try {
            return (MemorySegment) SecCertificateCopyDataHandle.invokeExact(certificate);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecCertificateCopyData", e);
        }
    }

    /**
     * Returns a policy object for evaluating SSL certificate chains.
     *
     * @param server   Specify true on the client side to return a policy for SSL server certificates.
     *                 See the explanation in {@link SecurityFrameworkUtil} for why we pass false.
     * @param hostname If you specify a value for this parameter (CFStringRef), the policy will require the specified
     *                 value to match the host name in the leaf certificate. Pass null to skip the host name check.
     * @return The policy object (SecPolicyRef). Call {@code CFRelease} to release the object when you are finished with it.
     * @see <a href="https://developer.apple.com/documentation/security/secpolicycreatessl(_:_:)">developer.apple.com</a>
     */
    static MemorySegment SecPolicyCreateSSL(boolean server, @Nullable MemorySegment hostname) {
        try {
            return (MemorySegment) SecPolicyCreateSSLHandle.invokeExact((byte) (server ? 1 : 0), nullable(hostname));
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecPolicyCreateSSL", e);
        }
    }

    /**
     * Returns a dictionary containing a policy’s properties.
     *
     * @param policyRef The policy (SecPolicyRef) from which properties should be copied.
     * @return A dictionary (CFDictionaryRef) with the policy's properties, see {@link #kSecPolicyOid}.
     * See <a href="https://developer.apple.com/documentation/security/certificate_key_and_trust_services/policies/security_policy_keys">Security Policy Keys</a>
     * for a list of valid keys. Call {@code CFRelease} to free the dictionary's memory when you are done with it.
     * @see <a href="https://developer.apple.com/documentation/security/1401915-secpolicycopyproperties">developer.apple.com</a>
     */
    static MemorySegment SecPolicyCopyProperties(@NotNull MemorySegment policyRef) {
        try {
            return (MemorySegment) SecPolicyCopyPropertiesHandle.invokeExact(policyRef);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecPolicyCopyProperties", e);
        }
    }

    /**
     * Creates a trust management object based on certificates and policies.
     *
     * @param certificates The certificate to be verified, plus any other certificates you think might be useful
     *                     for verifying the certificate. The certificate to be verified must be the first in the array.
     *                     If you want to specify only one certificate, you can pass a SecCertificateRef object;
     *                     otherwise, pass an array of SecCertificateRef objects.
     * @param policies     References to one or more policies to be evaluated. You can pass a single SecPolicyRef
     *                     object, or an array of one or more SecPolicyRef objects. If you pass in multiple policies,
     *                     all policies must verify for the certificate chain to be considered valid.
     * @param trust        On return, points to the newly created trust management object (SecTrustRef).
     *                     Call {@code CFRelease} to release this object when you are finished with it.
     * @return A result code, see {@link #errSecSuccess}.
     * @see <a href="https://developer.apple.com/documentation/security/sectrustcreatewithcertificates(_:_:_:)">developer.apple.com</a>
     */
    static int SecTrustCreateWithCertificates(@NotNull MemorySegment certificates, @NotNull MemorySegment policies, @NotNull MemorySegment trust) {
        try {
            return (int) SecTrustCreateWithCertificatesHandle.invokeExact(certificates, policies, trust);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecTrustCreateWithCertificates", e);
        }
    }

    /**
     * Evaluates trust for the specified certificate and policies.
     *
     * @param trust The trust management object (SecTrustRef) to evaluate. A trust management object includes
     *              the certificate to be verified plus the policy or policies to be used in evaluating trust.
     *              Use {@link #SecTrustCreateWithCertificates} to create a trust management object.
     * @param error An error pointer (CFErrorRef*) the method uses to return an error when trust evaluation fails.
     *              The returned error must be released with {@code CFRelease}.
     * @return true if the certificate is trusted; otherwise, false.
     * @see <a href="https://developer.apple.com/documentation/security/sectrustevaluatewitherror(_:_:)">developer.apple.com</a>
     */
    static boolean SecTrustEvaluateWithError(@NotNull MemorySegment trust, @NotNull MemorySegment error) {
        try {
            return (byte) SecTrustEvaluateWithErrorHandle.invokeExact(trust, error) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecTrustEvaluateWithError", e);
        }
    }

    /**
     * Obtains the trust settings for a certificate.
     *
     * @param certRef       The certificate (SecCertificateRef) for which you want the trust settings.
     * @param domain        The trust settings domain of the trust settings that you wish to obtain,
     *                      see {@code kSecTrustSettingsDomain*} constants.
     * @param trustSettings On return, an array (CFArrayRef) of CFDictionaryRef objects specifying the trust settings
     *                      for the certificate (usage constraints dictionaries, see {@code kSecTrustSettings*} keys).
     *                      Call {@code CFRelease} to release this object when you are finished with it.
     * @return A result code. Returns {@link #errSecItemNotFound} if no trust settings exist for the specified
     * certificate and domain.
     * @see <a href="https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting">developer.apple.com</a>
     */
    static int SecTrustSettingsCopyTrustSettings(@NotNull MemorySegment certRef, int domain, @NotNull MemorySegment trustSettings) {
        try {
            return (int) SecTrustSettingsCopyTrustSettingsHandle.invokeExact(certRef, domain, trustSettings);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecTrustSettingsCopyTrustSettings", e);
        }
    }

    /**
     * Returns a string explaining the meaning of a security result code.
     *
     * @param status   A result code of type OSStatus returned by a security function.
     * @param reserved Reserved for future use. Pass NULL for this parameter.
     * @return A human-readable string (CFStringRef) describing the result, or NULL if no string is available
     * for the specified result code. Call {@code CFRelease} to release this object when you are finished using it.
     * @see <a href="https://developer.apple.com/documentation/security/seccopyerrormessagestring(_:_:)">developer.apple.com</a>
     */
    static MemorySegment SecCopyErrorMessageString(int status, @Nullable MemorySegment reserved) {
        try {
            return (MemorySegment) SecCopyErrorMessageStringHandle.invokeExact(status, nullable(reserved));
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("SecCopyErrorMessageString", e);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // OSStatus helpers
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Human-readable text for an OSStatus via {@link #SecCopyErrorMessageString}, falling back to the numeric code.
     */
    static @NotNull String getErrorMessageString(int status) {
        MemorySegment string = SecCopyErrorMessageString(status, null);
        if (string.equals(NULL)) {
            return "OSStatus:" + status;
        }
        try {
            return stringValue(string);
        } finally {
            release(string);
        }
    }

    /**
     * Wraps an OSStatus into the same {@link CoreFoundationExt.Error} record used for CFErrorRef,
     * with {@link CoreFoundationExt#NSOSStatusErrorDomain} as the domain.
     */
    static @NotNull CoreFoundationExt.Error toError(int status) {
        return new CoreFoundationExt.Error(CoreFoundationExt.NSOSStatusErrorDomain, status, getErrorMessageString(status));
    }

    /**
     * @throws IllegalStateException if {@code status} is not {@link #errSecSuccess}
     */
    static void checkStatus(@NotNull String operation, int status) {
        if (status != errSecSuccess) {
            throw new IllegalStateException(operation + " failed: " + toError(status));
        }
    }

    // ---------------------------------------------------------------------------------------------------------------

    private static MemorySegment resolveStringConstant(String name) {
        return requireNonNull(LIBRARY.pointerVariable(name));
    }

    // a method call (not an inline `x == null ? NULL : x`) is required for invokeExact to see a MemorySegment argument
    private static MemorySegment nullable(@Nullable MemorySegment segment) {
        return segment == null ? NULL : segment;
    }

    private static long typeId(String getTypeIdFunction) {
        try {
            return (long) LIBRARY.downcall(getTypeIdFunction, of(JAVA_LONG)).invokeExact();
        } catch (Throwable e) {
            throw NativeLibrary.rethrow(getTypeIdFunction, e);
        }
    }
}
