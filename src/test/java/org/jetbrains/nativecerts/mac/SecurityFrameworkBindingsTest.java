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
import static org.jetbrains.nativecerts.mac.CoreFoundationExt.*;
import static org.jetbrains.nativecerts.mac.SecurityFramework.*;
import static org.junit.Assert.*;

public class SecurityFrameworkBindingsTest {
    @BeforeClass
    public static void requireMacOS() {
        Assume.assumeTrue(isMac);
    }

    @Test
    public void emptySettingsKeepDefaultTrust() {
        var settings = createArray();
        try {
            assertTrue(SecurityFrameworkUtil.matchesTrustSettings(settings, true));
        } finally {
            release(settings);
        }
    }

    @Test
    public void defaultResultRequiresSelfSignedCertificate() {
        assertTrue(matches(Map.of(), true));
        assertFalse(matches(Map.of(), false));
    }

    @Test
    public void acceptsOnlyTrustRootResult() {
        for (long result = 0; result <= 4; result++) {
            var number = CoreFoundationExtTest.number(result);
            try {
                assertEquals(result == TRUST_ROOT, matches(Map.of(TRUST_SETTINGS_RESULT, number), true));
                assertFalse(matches(Map.of(TRUST_SETTINGS_RESULT, number), false));
            } finally {
                release(number);
            }
        }
    }

    @Test
    public void rejectsUnknownConstraints() {
        var unknownKey = createString("Unknown trust constraint");
        try {
            assertFalse(matches(Map.of(unknownKey, TRUE), true));
        } finally {
            release(unknownKey);
        }
    }

    @Test
    public void acceptsSslPolicyAndRejectsBasicPolicy() {
        var ssl = (MemorySegment) POLICY_CREATE_SSL.invoke((byte) 0, NULL);
        var security = new NativeLibrary("/System/Library/Frameworks/Security.framework/Security");
        var basic = (MemorySegment) security.function("SecPolicyCreateBasicX509", of(ADDRESS)).invoke();
        try {
            assertTrue(matches(Map.of(TRUST_SETTINGS_POLICY, ssl), true));
            assertFalse(matches(Map.of(TRUST_SETTINGS_POLICY, basic), true));
        } finally {
            release(ssl);
            release(basic);
        }
    }

    @Test
    public void rejectsMalformedResultWithoutNativeTypeConfusion() {
        var string = createString("Not a number");
        try {
            assertThrows(ClassCastException.class, () -> matches(Map.of(TRUST_SETTINGS_RESULT, string), true));
        } finally {
            release(string);
        }
    }

    @Test
    public void rejectsUntrustedCertificateWithoutChangingKeychains() throws Exception {
        var coreFoundation = new NativeLibrary("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
        var security = new NativeLibrary("/System/Library/Frameworks/Security.framework/Security");
        var createData = coreFoundation.function("CFDataCreate", of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG));
        var createCertificate = security.function("SecCertificateCreateWithData", of(ADDRESS, ADDRESS, ADDRESS));
        try (var arena = Arena.ofConfined()) {
            var bytes = getTestCertificate().getEncoded();
            var data = requireNonNull((MemorySegment) createData.invoke(NULL,
                    arena.allocateFrom(JAVA_BYTE, bytes), (long) bytes.length));
            try {
                var certificate = requireNonNull((MemorySegment) createCertificate.invoke(NULL, data));
                try {
                    assertFalse(SecurityFrameworkUtil.isTrustedRoot(certificate));
                } finally {
                    release(certificate);
                }
            } finally {
                release(data);
            }
        }
    }

    private static boolean matches(Map<MemorySegment, MemorySegment> constraints, boolean selfSigned) {
        var dictionary = createDictionary(constraints);
        try {
            var settings = createArray(dictionary);
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
