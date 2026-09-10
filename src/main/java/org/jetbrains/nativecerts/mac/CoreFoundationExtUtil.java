package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static org.jetbrains.nativecerts.mac.CoreFoundationExt.*;

/**
 * Convenience layer on top of the raw {@link CoreFoundationExt} bindings: null and type checks, conversions
 * between Core Foundation objects and Java values, and creation of the collections used for keychain queries.
 * <p>
 * Every method that receives a pointer from native code verifies its {@code CFTypeID} before using it,
 * because a pointer of the wrong type would otherwise be interpreted as garbage without any error.
 */
final class CoreFoundationExtUtil {
    private CoreFoundationExtUtil() {
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Null / type checks and memory management
    // ---------------------------------------------------------------------------------------------------------------

    static @NotNull MemorySegment requireNonNull(@Nullable MemorySegment value) {
        if (value == null || value.equals(NULL)) {
            throw new IllegalStateException("The native framework returned a null object");
        }
        return value;
    }

    /**
     * Verifies that {@code value} is a non-null Core Foundation object of the expected type.
     *
     * @param expectedTypeId One of the {@code *_TYPE_ID} constants from {@link CoreFoundationExt}/{@link SecurityFramework}
     * @throws ClassCastException if the actual type differs, mirroring the {@code Unable to cast to ...} check
     *                            of the former JNA-based {@code CFTypeRef} subclasses
     */
    static void requireType(@Nullable MemorySegment value, long expectedTypeId) {
        long actualTypeId = CFGetTypeID(requireNonNull(value));
        if (actualTypeId != expectedTypeId) {
            throw new ClassCastException("Expected CFTypeID " + expectedTypeId + ", got " + actualTypeId);
        }
    }

    /**
     * {@link CoreFoundationExt#CFRelease} that tolerates NULL, for {@code finally} blocks.
     */
    static void release(@Nullable MemorySegment value) {
        if (value != null && !value.equals(NULL)) {
            CFRelease(value);
        }
    }

    static boolean equal(@NotNull MemorySegment first, @NotNull MemorySegment second) {
        return CFEqual(requireNonNull(first), requireNonNull(second));
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFArray
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Creates an immutable CFArray retaining the given objects.
     *
     * @return A new array; the caller must {@link #release} it.
     */
    static @NotNull MemorySegment createArray(@NotNull MemorySegment... values) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeValues = arena.allocate(ADDRESS, values.length);
            for (int i = 0; i < values.length; i++) {
                nativeValues.setAtIndex(ADDRESS, i, values[i]);
            }
            return requireNonNull(CFArrayCreate(null, nativeValues, values.length, kCFTypeArrayCallBacks));
        }
    }

    static long getArrayCount(@NotNull MemorySegment array) {
        requireType(array, ARRAY_TYPE_ID);
        return CFArrayGetCount(array);
    }

    /**
     * Bounds-checked {@link CoreFoundationExt#CFArrayGetValueAtIndex}.
     *
     * @return A borrowed reference, valid while {@code array} is alive
     */
    static @NotNull MemorySegment getValueAtIndex(@NotNull MemorySegment array, long index) {
        long count = getArrayCount(array);
        if (index < 0 || index >= count) {
            throw new IndexOutOfBoundsException("Array index " + index + ", count " + count);
        }
        return CFArrayGetValueAtIndex(array, index);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFDictionary
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Creates an immutable CFDictionary retaining the given keys and values.
     *
     * @return A new dictionary; the caller must {@link #release} it.
     */
    static @NotNull MemorySegment createDictionary(@NotNull Map<MemorySegment, MemorySegment> map) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keys = arena.allocate(ADDRESS, map.size());
            MemorySegment values = arena.allocate(ADDRESS, map.size());
            int i = 0;
            for (Map.Entry<MemorySegment, MemorySegment> entry : map.entrySet()) {
                keys.setAtIndex(ADDRESS, i, entry.getKey());
                values.setAtIndex(ADDRESS, i, entry.getValue());
                i++;
            }
            return requireNonNull(CFDictionaryCreate(null, keys, values, map.size(),
                    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks));
        }
    }

    static long getDictionaryCount(@NotNull MemorySegment dictionary) {
        requireType(dictionary, DICTIONARY_TYPE_ID);
        return CFDictionaryGetCount(dictionary);
    }

    /**
     * @return The borrowed value for {@code key}, or NULL if the dictionary has no such key
     */
    static @NotNull MemorySegment getValue(@NotNull MemorySegment dictionary, @NotNull MemorySegment key) {
        requireType(dictionary, DICTIONARY_TYPE_ID);
        return CFDictionaryGetValue(dictionary, key);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFString
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Creates a CFString from a Java string (equivalent of {@code CFSTR("...")}).
     *
     * @return A new string; the caller must {@link #release} it (constants in {@link SecurityFramework} live forever).
     */
    static @NotNull MemorySegment createString(@NotNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            return requireNonNull(CFStringCreateWithBytes(null, arena.allocateFrom(JAVA_BYTE, bytes), bytes.length,
                    kCFStringEncodingUTF8, false));
        }
    }

    /**
     * Converts a CFString to a Java string via {@code CFStringGetCString} in UTF-8.
     */
    static @NotNull String stringValue(@NotNull MemorySegment string) {
        requireType(string, STRING_TYPE_ID);
        long length = CFStringGetLength(string);
        // CFStringGetMaximumSizeForEncoding does not account for the terminating NUL
        long bufferSize = Math.addExact(CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8), 1);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buffer = arena.allocate(bufferSize);
            if (!CFStringGetCString(string, buffer, bufferSize, kCFStringEncodingUTF8)) {
                throw new IllegalStateException("CFStringGetCString failed");
            }
            return buffer.getString(0, StandardCharsets.UTF_8);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFNumber
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Reads a CFNumber as a signed 64-bit integer.
     */
    static long longValue(@NotNull MemorySegment number) {
        requireType(number, NUMBER_TYPE_ID);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment value = arena.allocate(JAVA_LONG);
            if (!CFNumberGetValue(number, kCFNumberSInt64Type, value)) {
                throw new IllegalStateException("CFNumberGetValue failed");
            }
            return value.get(JAVA_LONG, 0);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFData
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Copies the content of a CFData into a Java array.
     */
    static byte @NotNull [] getBytes(@NotNull MemorySegment data) {
        requireType(data, DATA_TYPE_ID);
        long length = CFDataGetLength(data);
        if (length == 0) {
            return new byte[0];
        }
        MemorySegment bytes = requireNonNull(CFDataGetBytePtr(data));
        // the returned pointer has zero length in FFM terms, widen it to the actual length before copying
        try (Arena arena = Arena.ofConfined()) {
            return bytes.reinterpret(length, arena, null).toArray(JAVA_BYTE);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Diagnostics
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * {@code CFCopyDescription} converted to a Java string, for logging.
     */
    static @NotNull String getDescription(@NotNull MemorySegment cfTypeRef) {
        MemorySegment description = requireNonNull(CFCopyDescription(requireNonNull(cfTypeRef)));
        try {
            return stringValue(description);
        } finally {
            release(description);
        }
    }

    /**
     * Unwraps a CFErrorRef into a Java {@link CoreFoundationExt.Error} (domain, code, description).
     */
    static @NotNull CoreFoundationExt.Error toError(@NotNull MemorySegment error) {
        requireType(error, ERROR_TYPE_ID);
        MemorySegment description = requireNonNull(CFErrorCopyDescription(error));
        try {
            return new CoreFoundationExt.Error(
                    stringValue(CFErrorGetDomain(error)),
                    CFErrorGetCode(error),
                    stringValue(description)
            );
        } finally {
            release(description);
        }
    }
}
