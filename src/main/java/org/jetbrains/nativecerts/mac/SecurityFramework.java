package org.jetbrains.nativecerts.mac;

import com.sun.jna.*;
import com.sun.jna.platform.mac.CoreFoundation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@SuppressWarnings("unused")
public interface SecurityFramework extends Library {

    SecurityFramework INSTANCE = Native.load("Security", SecurityFramework.class);

    /**
     * Returns a string explaining the meaning of a security result code.
     *
     * @param status
     *          A result code of type OSStatus returned by a security function.
     *          See <a href="https://developer.apple.com/documentation/security/1542001-security_framework_result_codes">Security Framework Result Codes</a> for a list of codes.
     * @param reserved
     *          Reserved for future use. Pass NULL for this parameter.
     * @return
     *          A human-readable string describing the result, or NULL if no string is available for the specified result code.
     *          Call the {@link CoreFoundation#CFRelease(CoreFoundation.CFTypeRef)} function to release this object when you are finished using it.
     *
     * @see <a href="https://developer.apple.com/documentation/security/1394686-seccopyerrormessagestring">developer.apple.com</a>
     */
    @Nullable
    CoreFoundation.CFStringRef SecCopyErrorMessageString(@NotNull OSStatus status, @Nullable Pointer reserved);

    /**
     * Obtains an array of all certificates that have trust settings in a specific trust settings domain.
     *
     * @param domain
     *          The trust settings domain for which you want a list of certificates.
     *          For possible values, see {@link SecTrustSettingsDomain}.
     * @param certArray
     *          On return, an array of {@link SecCertificateRef} objects representing the certificates that have
     *          trust settings in the specified domain. Call the {@link CoreFoundation#CFRelease(CoreFoundation.CFTypeRef)}
     *          function to release this object when you are finished with it.
     * @return
     *          A result code. See <a href="https://developer.apple.com/documentation/security/1542001-security_framework_result_codes">Security Framework Result Codes</a>.
     *          Returns {@link OSStatus#errSecNoTrustSettings} if no trust settings exist for the specified domain.
     *
     * @see <a href="https://developer.apple.com/documentation/security/1397413-sectrustsettingscopycertificates">developer.apple.com</a>
     */
    @NotNull
    OSStatus SecTrustSettingsCopyCertificates(@NotNull SecTrustSettingsDomain domain, @NotNull CFArrayRefByReference certArray);

    /**
     * Retrieves the common name of the subject of a certificate.
     *
     * @param certificate
     *          The certificate object from which to retrieve the common name.
     * @param commonName
     *          On return, points to the common name. Call the {@link CoreFoundation#CFRelease(CoreFoundation.CFTypeRef)} function to release this object when you are finished with it.
     * @return
     *          A result code. See {@link OSStatus}
     *
     * @see <a href="https://developer.apple.com/documentation/security/1394814-seccertificatecopycommonname">developer.apple.com</a>
     */
    @NotNull
    OSStatus SecCertificateCopyCommonName(@NotNull SecCertificateRef certificate, @NotNull CFStringRefByReference commonName);

    /**
     * @return
     *      The unique identifier of the opaque type to which a certificate object belongs.
     *
     * @see <a href="https://developer.apple.com/documentation/security/1396056-seccertificategettypeid">developer.apple.com</a>
     */
    CoreFoundation.CFTypeID SecCertificateGetTypeID();

    CoreFoundation.CFTypeID SEC_CERTIFICATE_TYPE_ID = INSTANCE.SecCertificateGetTypeID();

    /**
     * An abstract Core Foundation-type object representing an X.509 certificate.
     *
     * @see <a href="https://developer.apple.com/documentation/security/seccertificateref">developer.apple.com</a>
     */
    class SecCertificateRef extends CoreFoundation.CFTypeRef {
        public SecCertificateRef() {
        }

        public SecCertificateRef(Pointer p) {
            super(p);
            if (!isTypeID(SEC_CERTIFICATE_TYPE_ID)) {
                throw new ClassCastException("Unable to cast to SecCertificateRef. Type ID: " + getTypeID());
            }
        }
    }

    /**
     * Returns a DER representation of a certificate given a certificate object.
     *
     * @param certificate
     *          The certificate object for which you wish to return the DER (Distinguished Encoding Rules)
     *          representation of the X.509 certificate.
     * @return
     *          The DER representation of the certificate.
     *          Call the {@link CoreFoundation#CFRelease(CoreFoundation.CFTypeRef)} function to release this object
     *          when you are finished with it. Returns NULL if the data passed in the certificate parameter is
     *          not a valid certificate object.
     *
     * @see <a href="https://developer.apple.com/documentation/security/1396080-seccertificatecopydata">developer.apple.com</a>
     */
    CoreFoundation.CFDataRef SecCertificateCopyData(SecCertificateRef certificate);

    /**
     * A number indicating the effective trust setting for this usage constraints dictionary.
     *
     * @see <a href="https://developer.apple.com/documentation/security/ksectrustsettingsresult">developer.apple.com</a>
     */
    CoreFoundation.CFStringRef kSecTrustSettingsResult = CoreFoundation.CFStringRef.createCFString("kSecTrustSettingsResult");

    /**
     * Obtains the trust settings for a certificate.
     *
     * @param certRef
     *          The certificate for which you want the trust settings.
     *          Pass the value <a href="https://developer.apple.com/documentation/security/ksectrustsettingsdefaultrootcertsetting">kSecTrustSettingsDefaultRootCertSetting</a>
     *          to obtain the default root certificate trust settings for the domain.
     * @param domain
     *          The trust settings domain of the trust settings that you wish to obtain.
     *          For possible values, see {@link SecTrustSettingsDomain}.
     * @param trustSettings
     *          On return, an array of {@link com.sun.jna.platform.mac.CoreFoundation.CFDictionaryRef} objects
     *          specifying the trust settings for the certificate. For the contents of the dictionaries,
     *          see the discussion below. Call the {@link CoreFoundation#CFRelease(CoreFoundation.CFTypeRef)} function
     *          to release this object when you are finished with it.
     * @return
     *          A result code. See {@link OSStatus}. Returns {@link OSStatus#errSecItemNotFound} if no trust settings
     *          exist for the specified certificate and domain.
     *
     * @see <a href="https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting">https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting</a>
     */
    OSStatus SecTrustSettingsCopyTrustSettings(SecCertificateRef certRef, SecTrustSettingsDomain domain, CFArrayRefByReference trustSettings);

    /**
     * Trust settings returned in usage constraints dictionaries.
     *
     * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsresult">developer.apple.com</a>
     */
    class SecTrustSettingsResult extends NativeLong {
        /**
         * Never valid in a Trust Settings array or in an API call.
         */
        public static final SecTrustSettingsResult kSecTrustSettingsResultInvalid = new SecTrustSettingsResult(0);

        /**
         * Root cert is explicitly trusted
         */
        public static final SecTrustSettingsResult kSecTrustSettingsResultTrustRoot = new SecTrustSettingsResult(1);

        /**
         * Non-root cert is explicitly trusted
         */
        public static final SecTrustSettingsResult kSecTrustSettingsResultTrustAsRoot = new SecTrustSettingsResult(2);

        /**
         * Cert is explicitly distrusted
         */
        public static final SecTrustSettingsResult kSecTrustSettingsResultDeny = new SecTrustSettingsResult(3);

        /**
         * Neither trusted nor distrusted; evaluation proceeds as usual
         */
        public static final SecTrustSettingsResult kSecTrustSettingsResultUnspecified = new SecTrustSettingsResult(4);

        public SecTrustSettingsResult() {
        }

        public SecTrustSettingsResult(long value) {
            super(value);
        }
    }

    /**
     * Result codes common to many Security framework functions.
     *
     * @see <a href="https://developer.apple.com/documentation/security/1542001-security_framework_result_codes">developer.apple.com</a>
     */
    class OSStatus extends NativeLong {
        public static final OSStatus errSecSuccess = new OSStatus(0);

        /**
         * The specified item could not be found in the keychain.
         *
         * @see <a href="https://developer.apple.com/documentation/security/1542001-security_framework_result_codes/errsecitemnotfound">https://developer.apple.com/documentation/security/1542001-security_framework_result_codes/errsecitemnotfound</a>
         */
        public static final OSStatus errSecItemNotFound = new OSStatus(-25300);

        /**
         * No Trust Settings were found.
         * @see <a href="https://developer.apple.com/documentation/security/errsecnotrustsettings">https://developer.apple.com/documentation/security/errsecnotrustsettings</a>
         */
        public static final OSStatus errSecNoTrustSettings = new OSStatus(-25263);

        public OSStatus() {
        }

        public OSStatus(long value) {
            super(value);
        }

        @NotNull
        public String getErrorMessageString() {
            CoreFoundation.CFStringRef string = INSTANCE.SecCopyErrorMessageString(this, Pointer.NULL);
            if (string == null) {
                return "OSStatus:" + longValue();
            }
            try {
                return string.stringValue();
            }
            finally {
                string.release();
            }
        }
    }

    /**
     * The trust settings domains.
     *
     * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsdomain">developer.apple.com</a>
     */
    class SecTrustSettingsDomain extends NativeLong {
        /**
         * Per-user trust settings.
         *
         * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsdomain/user">developer.apple.com</a>
         */
        public static final SecTrustSettingsDomain user = new SecTrustSettingsDomain(0);

        /**
         * Locally administered, system-wide trust settings.
         * <p>
         * Administrator privileges are required to make changes to this domain.
         *
         * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsdomain/admin">developer.apple.com</a>
         */
        public static final SecTrustSettingsDomain admin = new SecTrustSettingsDomain(1);

        /**
         * System trust settings.
         * <p>
         * These trust settings are immutable and comprise the set of trusted root certificates supplied in macOS. These settings are read-only, even by root.
         *
         * @see <a href="https://developer.apple.com/documentation/security/sectrustsettingsdomain/system">developer.apple.com</a>
         */
        public static final SecTrustSettingsDomain system = new SecTrustSettingsDomain(2);

        public SecTrustSettingsDomain() {
        }

        public SecTrustSettingsDomain(long value) {
            super(value);
        }
    }
}
