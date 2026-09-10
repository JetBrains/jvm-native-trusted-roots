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
import static org.jetbrains.nativecerts.mac.CoreFoundationExt.*;
import static org.junit.Assert.*;

public class CoreFoundationExtTest {
    @BeforeClass
    public static void requireMacOS() {
        Assume.assumeTrue(isMac);
    }

    @Test
    public void stringsRoundTripAsUtf8() {
        for (var text : new String[]{"", "Trusted roots", "Grüße 世界 🔐"}) {
            var string = createString(text);
            try {
                assertEquals(text, stringValue(string));
                assertFalse(description(string).isEmpty() && !text.isEmpty());
            } finally {
                release(string);
            }
        }
    }

    @Test
    public void arraysRetainValuesAndCheckBounds() {
        var string = createString("Certificate");
        var array = createArray(string);
        release(string);
        try {
            assertEquals(1, arrayCount(array));
            assertEquals("Certificate", stringValue(arrayValue(array, 0)));
            assertThrows(IndexOutOfBoundsException.class, () -> arrayValue(array, -1));
            assertThrows(IndexOutOfBoundsException.class, () -> arrayValue(array, 1));
        } finally {
            release(array);
        }
    }

    @Test
    public void dictionariesCompareKeysByValue() {
        var key = createString("A key that does not fit in a tagged pointer");
        var equalKey = createString("A key that does not fit in a tagged pointer");
        var dictionary = createDictionary(Map.of(key, TRUE));
        release(key);
        try {
            assertEquals(1, dictionaryCount(dictionary));
            assertTrue(equal(TRUE, dictionaryValue(dictionary, equalKey)));
        } finally {
            release(dictionary);
            release(equalKey);
        }
    }

    @Test
    public void rejectsWrongObjectTypes() {
        var string = createString("Not an array or a number");
        try {
            assertThrows(ClassCastException.class, () -> arrayCount(string));
            assertThrows(ClassCastException.class, () -> numberValue(string));
        } finally {
            release(string);
        }
    }

    @Test
    public void readsSigned64BitNumbers() {
        var number = number(-25300);
        try {
            assertEquals(-25300, numberValue(number));
        } finally {
            release(number);
        }
    }

    @Test
    public void osStatusPreservesNegativeErrorCode() {
        var error = SecurityFramework.error(SecurityFramework.ITEM_NOT_FOUND);
        assertEquals(-25300, error.code());
        assertFalse(error.description().isEmpty());
    }

    static MemorySegment number(long value) {
        var library = new NativeLibrary("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
        var create = library.function("CFNumberCreate", of(ADDRESS, ADDRESS, JAVA_INT, ADDRESS));
        try (var arena = Arena.ofConfined()) {
            return requireNonNull((MemorySegment) create.invoke(NULL, 4, arena.allocateFrom(JAVA_LONG, value)));
        }
    }
}
