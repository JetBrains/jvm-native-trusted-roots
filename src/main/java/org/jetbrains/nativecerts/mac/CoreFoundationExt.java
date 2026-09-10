package org.jetbrains.nativecerts.mac;

import org.jetbrains.nativecerts.NativeLibrary;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.FunctionDescriptor.ofVoid;
import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

final class CoreFoundationExt {
    private static final NativeLibrary LIBRARY = new NativeLibrary(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
    private static final int UTF8 = 0x08000100;
    private static final NativeLibrary.Function RELEASE = LIBRARY.function("CFRelease", ofVoid(ADDRESS));
    private static final NativeLibrary.Function GET_TYPE_ID = LIBRARY.function("CFGetTypeID", of(JAVA_LONG, ADDRESS));
    private static final NativeLibrary.Function EQUAL = LIBRARY.function("CFEqual", of(JAVA_BYTE, ADDRESS, ADDRESS));
    private static final NativeLibrary.Function COPY_DESCRIPTION = LIBRARY.function("CFCopyDescription", of(ADDRESS, ADDRESS));
    private static final NativeLibrary.Function ARRAY_CREATE = LIBRARY.function("CFArrayCreate",
            of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
    private static final NativeLibrary.Function ARRAY_COUNT = LIBRARY.function("CFArrayGetCount", of(JAVA_LONG, ADDRESS));
    private static final NativeLibrary.Function ARRAY_VALUE = LIBRARY.function("CFArrayGetValueAtIndex", of(ADDRESS, ADDRESS, JAVA_LONG));
    private static final NativeLibrary.Function DICTIONARY_CREATE = LIBRARY.function("CFDictionaryCreate",
            of(ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
    private static final NativeLibrary.Function DICTIONARY_COUNT = LIBRARY.function("CFDictionaryGetCount", of(JAVA_LONG, ADDRESS));
    private static final NativeLibrary.Function DICTIONARY_VALUE = LIBRARY.function("CFDictionaryGetValue", of(ADDRESS, ADDRESS, ADDRESS));
    private static final NativeLibrary.Function STRING_CREATE = LIBRARY.function("CFStringCreateWithBytes",
            of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_BYTE));
    private static final NativeLibrary.Function STRING_LENGTH = LIBRARY.function("CFStringGetLength", of(JAVA_LONG, ADDRESS));
    private static final NativeLibrary.Function STRING_MAXIMUM_SIZE = LIBRARY.function("CFStringGetMaximumSizeForEncoding",
            of(JAVA_LONG, JAVA_LONG, JAVA_INT));
    private static final NativeLibrary.Function STRING_GET_C_STRING = LIBRARY.function("CFStringGetCString",
            of(JAVA_BYTE, ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT));
    private static final NativeLibrary.Function NUMBER_VALUE = LIBRARY.function("CFNumberGetValue", of(JAVA_BYTE, ADDRESS, JAVA_INT, ADDRESS));
    private static final NativeLibrary.Function DATA_LENGTH = LIBRARY.function("CFDataGetLength", of(JAVA_LONG, ADDRESS));
    private static final NativeLibrary.Function DATA_BYTES = LIBRARY.function("CFDataGetBytePtr", of(ADDRESS, ADDRESS));
    private static final NativeLibrary.Function ERROR_DOMAIN = LIBRARY.function("CFErrorGetDomain", of(ADDRESS, ADDRESS));
    private static final NativeLibrary.Function ERROR_CODE = LIBRARY.function("CFErrorGetCode", of(JAVA_LONG, ADDRESS));
    private static final NativeLibrary.Function ERROR_DESCRIPTION = LIBRARY.function("CFErrorCopyDescription", of(ADDRESS, ADDRESS));
    private static final long ARRAY_TYPE = typeId("CFArrayGetTypeID");
    private static final long DICTIONARY_TYPE = typeId("CFDictionaryGetTypeID");
    private static final long STRING_TYPE = typeId("CFStringGetTypeID");
    private static final long NUMBER_TYPE = typeId("CFNumberGetTypeID");
    private static final long DATA_TYPE = typeId("CFDataGetTypeID");
    private static final long ERROR_TYPE = typeId("CFErrorGetTypeID");
    static final MemorySegment TRUE = LIBRARY.symbol("kCFBooleanTrue").reinterpret(ADDRESS.byteSize()).get(ADDRESS, 0);

    static long typeId(String function) {
        return (long) LIBRARY.function(function, of(JAVA_LONG)).invoke();
    }

    static MemorySegment requireNonNull(MemorySegment value) {
        if (value.equals(NULL)) {
            throw new IllegalStateException("The native framework returned a null object");
        }
        return value;
    }

    static void requireType(MemorySegment value, long expectedType) {
        long actualType = (long) GET_TYPE_ID.invoke(requireNonNull(value));
        if (actualType != expectedType) {
            throw new ClassCastException("Expected CFTypeID " + expectedType + ", got " + actualType);
        }
    }

    static void release(MemorySegment value) {
        if (!value.equals(NULL)) {
            RELEASE.invoke(value);
        }
    }

    static boolean equal(MemorySegment first, MemorySegment second) {
        return (byte) EQUAL.invoke(requireNonNull(first), requireNonNull(second)) != 0;
    }

    static MemorySegment createArray(MemorySegment... values) {
        try (var arena = Arena.ofConfined()) {
            var pointers = arena.allocate(ADDRESS, values.length);
            for (int index = 0; index < values.length; index++) {
                pointers.setAtIndex(ADDRESS, index, values[index]);
            }
            return requireNonNull((MemorySegment) ARRAY_CREATE.invoke(NULL, pointers, (long) values.length,
                    LIBRARY.symbol("kCFTypeArrayCallBacks")));
        }
    }

    static long arrayCount(MemorySegment array) {
        requireType(array, ARRAY_TYPE);
        return (long) ARRAY_COUNT.invoke(array);
    }

    static MemorySegment arrayValue(MemorySegment array, long index) {
        long count = arrayCount(array);
        if (index < 0 || index >= count) {
            throw new IndexOutOfBoundsException("Array index " + index + ", count " + count);
        }
        return (MemorySegment) ARRAY_VALUE.invoke(array, index);
    }

    static MemorySegment createDictionary(Map<MemorySegment, MemorySegment> values) {
        try (var arena = Arena.ofConfined()) {
            var keys = arena.allocate(ADDRESS, values.size());
            var pointers = arena.allocate(ADDRESS, values.size());
            int index = 0;
            for (var entry : values.entrySet()) {
                keys.setAtIndex(ADDRESS, index, entry.getKey());
                pointers.setAtIndex(ADDRESS, index, entry.getValue());
                index++;
            }
            return requireNonNull((MemorySegment) DICTIONARY_CREATE.invoke(NULL, keys, pointers, (long) values.size(),
                    LIBRARY.symbol("kCFTypeDictionaryKeyCallBacks"), LIBRARY.symbol("kCFTypeDictionaryValueCallBacks")));
        }
    }

    static long dictionaryCount(MemorySegment dictionary) {
        requireType(dictionary, DICTIONARY_TYPE);
        return (long) DICTIONARY_COUNT.invoke(dictionary);
    }

    static MemorySegment dictionaryValue(MemorySegment dictionary, MemorySegment key) {
        requireType(dictionary, DICTIONARY_TYPE);
        return (MemorySegment) DICTIONARY_VALUE.invoke(dictionary, key);
    }

    static MemorySegment createString(String value) {
        try (var arena = Arena.ofConfined()) {
            var bytes = value.getBytes(StandardCharsets.UTF_8);
            return requireNonNull((MemorySegment) STRING_CREATE.invoke(NULL, arena.allocateFrom(JAVA_BYTE, bytes),
                    (long) bytes.length, UTF8, (byte) 0));
        }
    }

    static String stringValue(MemorySegment string) {
        requireType(string, STRING_TYPE);
        long length = (long) STRING_LENGTH.invoke(string);
        long capacity = Math.addExact((long) STRING_MAXIMUM_SIZE.invoke(length, UTF8), 1);
        try (var arena = Arena.ofConfined()) {
            var buffer = arena.allocate(capacity);
            if ((byte) STRING_GET_C_STRING.invoke(string, buffer, capacity, UTF8) == 0) {
                throw new IllegalStateException("CFStringGetCString failed");
            }
            return buffer.getString(0, StandardCharsets.UTF_8);
        }
    }

    static long numberValue(MemorySegment number) {
        requireType(number, NUMBER_TYPE);
        try (var arena = Arena.ofConfined()) {
            var value = arena.allocate(JAVA_LONG);
            if ((byte) NUMBER_VALUE.invoke(number, 4, value) == 0) {
                throw new IllegalStateException("CFNumberGetValue failed");
            }
            return value.get(JAVA_LONG, 0);
        }
    }

    static byte[] dataBytes(MemorySegment data) {
        requireType(data, DATA_TYPE);
        long length = (long) DATA_LENGTH.invoke(data);
        if (length == 0) {
            return new byte[0];
        }
        var bytes = requireNonNull((MemorySegment) DATA_BYTES.invoke(data));
        try (var arena = Arena.ofConfined()) {
            return bytes.reinterpret(length, arena, null).toArray(JAVA_BYTE);
        }
    }

    static String description(MemorySegment value) {
        var description = requireNonNull((MemorySegment) COPY_DESCRIPTION.invoke(requireNonNull(value)));
        try {
            return stringValue(description);
        } finally {
            release(description);
        }
    }

    static Error error(MemorySegment error) {
        requireType(error, ERROR_TYPE);
        var description = requireNonNull((MemorySegment) ERROR_DESCRIPTION.invoke(error));
        try {
            return new Error(stringValue((MemorySegment) ERROR_DOMAIN.invoke(error)),
                    (long) ERROR_CODE.invoke(error), stringValue(description));
        } finally {
            release(description);
        }
    }

    record Error(String domain, long code, String description) {
    }

    private CoreFoundationExt() {
    }
}
