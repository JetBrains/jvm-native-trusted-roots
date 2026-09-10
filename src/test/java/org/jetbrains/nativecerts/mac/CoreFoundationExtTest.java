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
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static org.jetbrains.nativecerts.NativeTrustedRootsInternalUtils.isMac;
import static org.jetbrains.nativecerts.mac.CoreFoundationExt.kCFBooleanTrue;
import static org.jetbrains.nativecerts.mac.CoreFoundationExt.kCFNumberSInt64Type;
import static org.jetbrains.nativecerts.mac.CoreFoundationExtUtil.*;
import static org.junit.Assert.*;

/**
 * Round-trip tests of the Core Foundation conversions in {@link CoreFoundationExtUtil}.
 */
public class CoreFoundationExtTest {
    @BeforeClass
    public static void requireMacOS() {
        Assume.assumeTrue(isMac);
    }

    @Test
    public void stringsRoundTripAsUtf8() {
        for (String text : new String[]{"", "Trusted roots", "Grüße 世界 🔐"}) {
            MemorySegment string = createString(text);
            try {
                assertEquals(text, stringValue(string));
                assertFalse(getDescription(string).isEmpty() && !text.isEmpty());
            } finally {
                release(string);
            }
        }
    }

    @Test
    public void arraysRetainValuesAndCheckBounds() {
        MemorySegment string = createString("Certificate");
        MemorySegment array = createArray(string);
        // the array retained the string (kCFTypeArrayCallBacks), so our reference can go
        release(string);
        try {
            assertEquals(1, getArrayCount(array));
            assertEquals("Certificate", stringValue(getValueAtIndex(array, 0)));
            assertThrows(IndexOutOfBoundsException.class, () -> getValueAtIndex(array, -1));
            assertThrows(IndexOutOfBoundsException.class, () -> getValueAtIndex(array, 1));
        } finally {
            release(array);
        }
    }

    @Test
    public void dictionariesCompareKeysByValue() {
        // kCFTypeDictionaryKeyCallBacks compare keys with CFEqual, not by pointer:
        // that is what makes the CFSTR-style kSecTrustSettings* keys created on our side match the framework's ones
        MemorySegment key = createString("A key that does not fit in a tagged pointer");
        MemorySegment equalKey = createString("A key that does not fit in a tagged pointer");
        MemorySegment dictionary = createDictionary(Map.of(key, kCFBooleanTrue));
        release(key);
        try {
            assertEquals(1, getDictionaryCount(dictionary));
            assertTrue(equal(kCFBooleanTrue, getValue(dictionary, equalKey)));
        } finally {
            release(dictionary);
            release(equalKey);
        }
    }

    @Test
    public void rejectsWrongObjectTypes() {
        MemorySegment string = createString("Not an array or a number");
        try {
            assertThrows(ClassCastException.class, () -> getArrayCount(string));
            assertThrows(ClassCastException.class, () -> longValue(string));
        } finally {
            release(string);
        }
    }

    @Test
    public void readsSigned64BitNumbers() {
        MemorySegment number = number(-25300);
        try {
            assertEquals(-25300, longValue(number));
        } finally {
            release(number);
        }
    }

    @Test
    public void osStatusPreservesNegativeErrorCode() {
        CoreFoundationExt.Error error = SecurityFramework.toError(SecurityFramework.errSecItemNotFound);
        assertEquals(CoreFoundationExt.NSOSStatusErrorDomain, error.domain());
        assertEquals(-25300, error.code());
        assertFalse(error.description().isEmpty());
    }

    /**
     * {@code CFNumberCreate(NULL, kCFNumberSInt64Type, &value)}; the caller must release the result.
     */
    static MemorySegment number(long value) {
        NativeLibrary library = new NativeLibrary(CoreFoundationExt.CORE_FOUNDATION_LIBRARY_PATH);
        var CFNumberCreate = library.downcall("CFNumberCreate", of(ADDRESS, ADDRESS, JAVA_INT, ADDRESS));
        try (Arena arena = Arena.ofConfined()) {
            return requireNonNull((MemorySegment) CFNumberCreate.invokeExact(NULL, kCFNumberSInt64Type, arena.allocateFrom(JAVA_LONG, value)));
        } catch (Throwable e) {
            throw new AssertionError(e);
        }
    }
}
