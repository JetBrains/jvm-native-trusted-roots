package org.jetbrains.nativecerts.mac;

import org.jetbrains.nativecerts.NativeLibrary;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Map;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static org.jetbrains.nativecerts.NativeCertsTestUtil.getTestCertificate;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isMac;
import static org.jetbrains.nativecerts.mac.CoreFoundationExtUtil.*;
import static org.jetbrains.nativecerts.mac.SecurityFramework.*;
import static org.junit.Assert.*;

/**
 * Tests of the trust settings interpretation ({@link SecurityFrameworkUtil#matchesTrustSettings}) with synthetic
 * usage constraints dictionaries, and of the bindings themselves. These tests do not modify any keychain.
 */
public class SecurityFrameworkBindingsTest {
    @BeforeClass
    public static void requireMacOS() {
        Assume.assumeTrue(isMac);
    }

    @Test
    public void emptySettingsKeepDefaultTrust() {
        // "An empty trust settings array means always trust this certificate"
        MemorySegment settings = createArray();
        try {
            assertTrue(SecurityFrameworkUtil.matchesTrustSettings(settings, true));
        } finally {
            release(settings);
        }
    }

    @Test
    public void defaultResultRequiresSelfSignedCertificate() {
        // missing kSecTrustSettingsResult => kSecTrustSettingsResultTrustRoot, valid only for a self-signed certificate
        assertTrue(matches(Map.of(), true));
        assertFalse(matches(Map.of(), false));
    }

    @Test
    public void acceptsOnlyTrustRootResult() {
        for (long result = kSecTrustSettingsResultInvalid; result <= kSecTrustSettingsResultUnspecified; result++) {
            MemorySegment number = CoreFoundationExtTest.number(result);
            try {
                assertEquals(result == kSecTrustSettingsResultTrustRoot, matches(Map.of(kSecTrustSettingsResult, number), true));
                assertFalse(matches(Map.of(kSecTrustSettingsResult, number), false));
            } finally {
                release(number);
            }
        }
    }

    @Test
    public void rejectsUnknownConstraints() {
        MemorySegment unknownKey = createString("Unknown trust constraint");
        try {
            assertFalse(matches(Map.of(unknownKey, CoreFoundationExt.kCFBooleanTrue), true));
        } finally {
            release(unknownKey);
        }
    }

    @Test
    public void acceptsSslPolicyAndRejectsBasicPolicy() {
        MemorySegment ssl = requireNonNull(SecPolicyCreateSSL(false, null));
        NativeLibrary security = new NativeLibrary(SECURITY_FRAMEWORK_LIBRARY_PATH);
        MemorySegment basic;
        try {
            basic = (MemorySegment) security.downcall("SecPolicyCreateBasicX509", of(ADDRESS)).invokeExact();
        } catch (Throwable e) {
            throw new AssertionError(e);
        }
        try {
            assertTrue(matches(Map.of(kSecTrustSettingsPolicy, ssl), true));
            assertFalse(matches(Map.of(kSecTrustSettingsPolicy, basic), true));
        } finally {
            release(ssl);
            release(basic);
        }
    }

    @Test
    public void rejectsMalformedResultWithoutNativeTypeConfusion() {
        MemorySegment string = createString("Not a number");
        try {
            assertThrows(ClassCastException.class, () -> matches(Map.of(kSecTrustSettingsResult, string), true));
        } finally {
            release(string);
        }
    }

    @Test
    public void rejectsUntrustedCertificateWithoutChangingKeychains() throws Exception {
        NativeLibrary coreFoundation = new NativeLibrary(CoreFoundationExt.CORE_FOUNDATION_LIBRARY_PATH);
        NativeLibrary security = new NativeLibrary(SECURITY_FRAMEWORK_LIBRARY_PATH);
        var CFDataCreate = coreFoundation.downcall("CFDataCreate", of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG));
        var SecCertificateCreateWithData = security.downcall("SecCertificateCreateWithData", of(ADDRESS, ADDRESS, ADDRESS));
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = getTestCertificate().getEncoded();
            MemorySegment data = requireNonNull((MemorySegment) CFDataCreate.invokeExact(NULL,
                    arena.allocateFrom(JAVA_BYTE, bytes), (long) bytes.length));
            try {
                MemorySegment certificate = requireNonNull((MemorySegment) SecCertificateCreateWithData.invokeExact(NULL, data));
                try {
                    requireType(certificate, SEC_CERTIFICATE_TYPE_ID);
                    assertFalse(SecurityFrameworkUtil.isTrustedRoot(certificate));
                } finally {
                    release(certificate);
                }
            } finally {
                release(data);
            }
        } catch (Throwable e) {
            if (e instanceof Exception exception) {
                throw exception;
            }
            throw new AssertionError(e);
        }
    }

    private static boolean matches(Map<MemorySegment, MemorySegment> constraints, boolean selfSigned) {
        MemorySegment dictionary = createDictionary(constraints);
        try {
            MemorySegment settings = createArray(dictionary);
            try {
                return SecurityFrameworkUtil.matchesTrustSettings(settings, selfSigned);
            } finally {
                release(settings);
            }
        } finally {
            release(dictionary);
        }
    }
}
