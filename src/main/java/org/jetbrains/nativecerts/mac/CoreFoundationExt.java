package org.jetbrains.nativecerts.mac;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeLibrary;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.FunctionDescriptor.ofVoid;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Raw bindings to the parts of CoreFoundation used by {@link SecurityFrameworkUtil}.
 * <p>
 * Every Core Foundation object is represented as an opaque pointer ({@link MemorySegment}). A method named after
 * a native function has the same signature as the C function (C types mapped as {@code CFIndex/CFTypeID -> long},
 * {@code Boolean -> boolean}, {@code CFStringEncoding/CFNumberType -> int}, all {@code *Ref -> MemorySegment}).
 * Memory ownership follows the
 * <a href="https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFMemoryMgmt/Concepts/Ownership.html">Create/Get rules</a>:
 * objects returned by {@code *Create*}/{@code *Copy*} functions must be released with {@link #CFRelease},
 * objects returned by {@code *Get*} functions are borrowed.
 * <p>
 * Higher-level helpers (type checks, Java conversions) live in {@link CoreFoundationExtUtil}.
 */
@SuppressWarnings({"unused", "SpellCheckingInspection"})
final class CoreFoundationExt {
    static final String CORE_FOUNDATION_LIBRARY_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    private static final NativeLibrary LIBRARY = new NativeLibrary(CORE_FOUNDATION_LIBRARY_PATH);

    private CoreFoundationExt() {
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Memory management and type identification
    // ---------------------------------------------------------------------------------------------------------------

    private static final MethodHandle CFReleaseHandle = LIBRARY.downcall("CFRelease", ofVoid(ADDRESS));
    private static final MethodHandle CFGetTypeIDHandle = LIBRARY.downcall("CFGetTypeID", of(JAVA_LONG, ADDRESS));
    private static final MethodHandle CFEqualHandle = LIBRARY.downcall("CFEqual", of(JAVA_BYTE, ADDRESS, ADDRESS));
    private static final MethodHandle CFCopyDescriptionHandle = LIBRARY.downcall("CFCopyDescription", of(ADDRESS, ADDRESS));

    /**
     * Releases a Core Foundation object. Must not be called with NULL (use {@link CoreFoundationExtUtil#release}).
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfrelease(_:)">developer.apple.com</a>
     */
    static void CFRelease(@NotNull MemorySegment cf) {
        try {
            CFReleaseHandle.invokeExact(cf);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFRelease", e);
        }
    }

    /**
     * Returns the unique identifier of an opaque type to which a Core Foundation object belongs.
     * Used to verify the actual type of a pointer before treating it as an array, a string, etc.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfgettypeid(_:)">developer.apple.com</a>
     */
    static long CFGetTypeID(@NotNull MemorySegment cf) {
        try {
            return (long) CFGetTypeIDHandle.invokeExact(cf);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFGetTypeID", e);
        }
    }

    /**
     * Determines whether two Core Foundation objects are considered equal.
     *
     * @param cf1 A CFType object to compare to cf2.
     * @param cf2 A CFType object to compare to cf1.
     * @return true if cf1 and cf2 are of the same type and considered equal, otherwise false.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/1521287-cfequal">developer.apple.com</a>
     */
    static boolean CFEqual(@NotNull MemorySegment cf1, @NotNull MemorySegment cf2) {
        try {
            return (byte) CFEqualHandle.invokeExact(cf1, cf2) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFEqual", e);
        }
    }

    /**
     * Returns a textual description of a Core Foundation object (used for logging only).
     *
     * @return A CFString. Ownership follows the Create Rule: release it with {@link #CFRelease}.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfcopydescription(_:)">developer.apple.com</a>
     */
    static MemorySegment CFCopyDescription(@NotNull MemorySegment cf) {
        try {
            return (MemorySegment) CFCopyDescriptionHandle.invokeExact(cf);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFCopyDescription", e);
        }
    }

    /**
     * {@code CFTypeID}s of the types we handle, resolved once via the corresponding {@code *GetTypeID} functions.
     * Type IDs are not stable constants and must be queried at runtime.
     */
    static final long ARRAY_TYPE_ID = typeId("CFArrayGetTypeID");
    static final long DICTIONARY_TYPE_ID = typeId("CFDictionaryGetTypeID");
    static final long STRING_TYPE_ID = typeId("CFStringGetTypeID");
    static final long NUMBER_TYPE_ID = typeId("CFNumberGetTypeID");
    static final long DATA_TYPE_ID = typeId("CFDataGetTypeID");
    static final long ERROR_TYPE_ID = typeId("CFErrorGetTypeID");

    private static long typeId(String getTypeIdFunction) {
        try {
            return (long) LIBRARY.downcall(getTypeIdFunction, of(JAVA_LONG)).invokeExact();
        } catch (Throwable e) {
            throw NativeLibrary.rethrow(getTypeIdFunction, e);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFBoolean
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Boolean true value.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/kcfbooleantrue">developer.apple.com</a>
     */
    static final MemorySegment kCFBooleanTrue = resolveBoolean("kCFBooleanTrue", true);

    private static MemorySegment resolveBoolean(String name, boolean expectedValue) {
        MemorySegment value = LIBRARY.pointerVariable(name);
        boolean actualValue;
        try {
            actualValue = (byte) LIBRARY.downcall("CFBooleanGetValue", of(JAVA_BYTE, ADDRESS)).invokeExact(value) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFBooleanGetValue", e);
        }
        if (actualValue != expectedValue) {
            throw new IllegalStateException("Expected " + name + " to be " + expectedValue + ", but got " + actualValue);
        }
        return value;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFArray
    // ---------------------------------------------------------------------------------------------------------------

    private static final MethodHandle CFArrayCreateHandle = LIBRARY.downcall("CFArrayCreate",
            of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
    private static final MethodHandle CFArrayGetCountHandle = LIBRARY.downcall("CFArrayGetCount", of(JAVA_LONG, ADDRESS));
    private static final MethodHandle CFArrayGetValueAtIndexHandle = LIBRARY.downcall("CFArrayGetValueAtIndex",
            of(ADDRESS, ADDRESS, JAVA_LONG));

    /**
     * Predefined {@code CFArrayCallBacks} structure containing a set of callbacks appropriate for use when
     * the values in a CFArray are all CFType-derived objects (the array retains them on creation and releases
     * them when the array is released).
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/kcftypearraycallbacks">developer.apple.com</a>
     */
    static final MemorySegment kCFTypeArrayCallBacks = LIBRARY.symbol("kCFTypeArrayCallBacks");

    /**
     * Creates a new immutable array with the given values.
     *
     * @param allocator The allocator to use to allocate memory for the new array and its storage for values.
     *                  Pass NULL to use the current default allocator.
     * @param values    A C array of the pointer-sized values to be in the new array.
     * @param numValues The number of values to copy from the {@code values} C array into the new array.
     * @param callBacks A pointer to a {@code CFArrayCallBacks} structure, see {@link #kCFTypeArrayCallBacks}.
     * @return A new immutable array, or NULL if there was a problem creating the object.
     * Ownership follows the Create Rule.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfarraycreate(_:_:_:_:)">developer.apple.com</a>
     */
    static MemorySegment CFArrayCreate(@Nullable MemorySegment allocator, @NotNull MemorySegment values, long numValues, @NotNull MemorySegment callBacks) {
        try {
            return (MemorySegment) CFArrayCreateHandle.invokeExact(nullable(allocator), values, numValues, callBacks);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFArrayCreate", e);
        }
    }

    /**
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfarraygetcount(_:)">developer.apple.com</a>
     */
    static long CFArrayGetCount(@NotNull MemorySegment theArray) {
        try {
            return (long) CFArrayGetCountHandle.invokeExact(theArray);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFArrayGetCount", e);
        }
    }

    /**
     * @param idx The index of the value to retrieve. If the index is outside the index space of the array
     *            (0 to N-1 inclusive, where N is the count of the array), the behavior is undefined,
     *            so callers must check bounds first (see {@link CoreFoundationExtUtil#getValueAtIndex}).
     * @return The borrowed value at the given index (Get Rule).
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfarraygetvalueatindex(_:_:)">developer.apple.com</a>
     */
    static MemorySegment CFArrayGetValueAtIndex(@NotNull MemorySegment theArray, long idx) {
        try {
            return (MemorySegment) CFArrayGetValueAtIndexHandle.invokeExact(theArray, idx);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFArrayGetValueAtIndex", e);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFDictionary
    // ---------------------------------------------------------------------------------------------------------------

    private static final MethodHandle CFDictionaryCreateHandle = LIBRARY.downcall("CFDictionaryCreate",
            of(ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
    private static final MethodHandle CFDictionaryGetCountHandle = LIBRARY.downcall("CFDictionaryGetCount", of(JAVA_LONG, ADDRESS));
    private static final MethodHandle CFDictionaryGetValueHandle = LIBRARY.downcall("CFDictionaryGetValue",
            of(ADDRESS, ADDRESS, ADDRESS));

    /**
     * Predefined callbacks for CFType-derived dictionary keys (retain/release/CFEqual/CFHash).
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/kcftypedictionarykeycallbacks">developer.apple.com</a>
     */
    static final MemorySegment kCFTypeDictionaryKeyCallBacks = LIBRARY.symbol("kCFTypeDictionaryKeyCallBacks");

    /**
     * Predefined callbacks for CFType-derived dictionary values.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/kcftypedictionaryvaluecallbacks">developer.apple.com</a>
     */
    static final MemorySegment kCFTypeDictionaryValueCallBacks = LIBRARY.symbol("kCFTypeDictionaryValueCallBacks");

    /**
     * Creates an immutable dictionary containing the specified key-value pairs.
     *
     * @param allocator      The allocator to use, NULL for the default allocator.
     * @param keys           A C array of the pointer-sized keys.
     * @param values         A C array of the pointer-sized values, parallel to {@code keys}.
     * @param numValues      The number of key-value pairs.
     * @param keyCallBacks   See {@link #kCFTypeDictionaryKeyCallBacks}. With these callbacks keys are compared
     *                       with {@code CFEqual}, so two distinct CFString objects with the same text match.
     * @param valueCallBacks See {@link #kCFTypeDictionaryValueCallBacks}.
     * @return A new dictionary, or NULL if there was a problem creating the object. Ownership follows the Create Rule.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfdictionarycreate(_:_:_:_:_:_:)">developer.apple.com</a>
     */
    static MemorySegment CFDictionaryCreate(@Nullable MemorySegment allocator,
                                            @NotNull MemorySegment keys,
                                            @NotNull MemorySegment values,
                                            long numValues,
                                            @NotNull MemorySegment keyCallBacks,
                                            @NotNull MemorySegment valueCallBacks) {
        try {
            return (MemorySegment) CFDictionaryCreateHandle.invokeExact(nullable(allocator), keys, values, numValues, keyCallBacks, valueCallBacks);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFDictionaryCreate", e);
        }
    }

    /**
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfdictionarygetcount(_:)">developer.apple.com</a>
     */
    static long CFDictionaryGetCount(@NotNull MemorySegment theDict) {
        try {
            return (long) CFDictionaryGetCountHandle.invokeExact(theDict);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFDictionaryGetCount", e);
        }
    }

    /**
     * @return The borrowed value associated with key, or NULL if no such key exists (Get Rule).
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfdictionarygetvalue(_:_:)">developer.apple.com</a>
     */
    static MemorySegment CFDictionaryGetValue(@NotNull MemorySegment theDict, @NotNull MemorySegment key) {
        try {
            return (MemorySegment) CFDictionaryGetValueHandle.invokeExact(theDict, key);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFDictionaryGetValue", e);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFString
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * {@code CFStringEncoding} value for UTF-8.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfstringbuiltinencodings/utf8">developer.apple.com</a>
     */
    static final int kCFStringEncodingUTF8 = 0x08000100;

    private static final MethodHandle CFStringCreateWithBytesHandle = LIBRARY.downcall("CFStringCreateWithBytes",
            of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_BYTE));
    private static final MethodHandle CFStringGetLengthHandle = LIBRARY.downcall("CFStringGetLength", of(JAVA_LONG, ADDRESS));
    private static final MethodHandle CFStringGetMaximumSizeForEncodingHandle = LIBRARY.downcall("CFStringGetMaximumSizeForEncoding",
            of(JAVA_LONG, JAVA_LONG, JAVA_INT));
    private static final MethodHandle CFStringGetCStringHandle = LIBRARY.downcall("CFStringGetCString",
            of(JAVA_BYTE, ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT));

    /**
     * Creates a string from a buffer containing characters in a specified encoding.
     *
     * @param allocator                NULL for the default allocator.
     * @param bytes                    A buffer containing characters in the encoding specified by {@code encoding}.
     * @param numBytes                 The number of bytes in the buffer.
     * @param encoding                 The encoding of the characters, see {@link #kCFStringEncodingUTF8}.
     * @param isExternalRepresentation true if the characters in the byte buffer are in an "external representation"
     *                                 format (i.e. may contain a BOM); we always pass false.
     * @return An immutable string, or NULL if there was a problem creating the object. Ownership follows the Create Rule.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfstringcreatewithbytes(_:_:_:_:_:)">developer.apple.com</a>
     */
    static MemorySegment CFStringCreateWithBytes(@Nullable MemorySegment allocator,
                                                 @NotNull MemorySegment bytes,
                                                 long numBytes,
                                                 int encoding,
                                                 boolean isExternalRepresentation) {
        try {
            return (MemorySegment) CFStringCreateWithBytesHandle.invokeExact(nullable(allocator), bytes, numBytes, encoding,
                    (byte) (isExternalRepresentation ? 1 : 0));
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFStringCreateWithBytes", e);
        }
    }

    /**
     * @return The number (in terms of UTF-16 code pairs) of characters stored in the string.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfstringgetlength(_:)">developer.apple.com</a>
     */
    static long CFStringGetLength(@NotNull MemorySegment theString) {
        try {
            return (long) CFStringGetLengthHandle.invokeExact(theString);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFStringGetLength", e);
        }
    }

    /**
     * Returns the maximum number of bytes a string of a specified length (in Unicode characters) will take up
     * if encoded in a specified encoding. Does not include the terminating NUL.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfstringgetmaximumsizeforencoding(_:_:)">developer.apple.com</a>
     */
    static long CFStringGetMaximumSizeForEncoding(long length, int encoding) {
        try {
            return (long) CFStringGetMaximumSizeForEncodingHandle.invokeExact(length, encoding);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFStringGetMaximumSizeForEncoding", e);
        }
    }

    /**
     * Copies the character contents of a string to a local C string buffer after converting the characters
     * to a given encoding.
     *
     * @param buffer     The C string buffer into which to copy the string. The buffer must be at least
     *                   {@code bufferSize} bytes in length and receives a terminating NUL.
     * @param bufferSize The length of buffer in bytes.
     * @return true upon success or false if the conversion fails or the provided buffer is too small.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfstringgetcstring(_:_:_:_:)">developer.apple.com</a>
     */
    static boolean CFStringGetCString(@NotNull MemorySegment theString, @NotNull MemorySegment buffer, long bufferSize, int encoding) {
        try {
            return (byte) CFStringGetCStringHandle.invokeExact(theString, buffer, bufferSize, encoding) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFStringGetCString", e);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFNumber
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * {@code CFNumberType} for a signed 64-bit integer.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfnumbertype/sint64type">developer.apple.com</a>
     */
    static final int kCFNumberSInt64Type = 4;

    private static final MethodHandle CFNumberGetValueHandle = LIBRARY.downcall("CFNumberGetValue",
            of(JAVA_BYTE, ADDRESS, JAVA_INT, ADDRESS));

    /**
     * Obtains the value of a CFNumber object cast to a specified type.
     *
     * @param theType  See {@link #kCFNumberSInt64Type}.
     * @param valuePtr On return, contains the value of {@code number}; must point to at least 8 bytes for SInt64.
     * @return true if the operation was successful, otherwise false (e.g. lossy conversion).
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfnumbergetvalue(_:_:_:)">developer.apple.com</a>
     */
    static boolean CFNumberGetValue(@NotNull MemorySegment number, int theType, @NotNull MemorySegment valuePtr) {
        try {
            return (byte) CFNumberGetValueHandle.invokeExact(number, theType, valuePtr) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFNumberGetValue", e);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFData
    // ---------------------------------------------------------------------------------------------------------------

    private static final MethodHandle CFDataGetLengthHandle = LIBRARY.downcall("CFDataGetLength", of(JAVA_LONG, ADDRESS));
    private static final MethodHandle CFDataGetBytePtrHandle = LIBRARY.downcall("CFDataGetBytePtr", of(ADDRESS, ADDRESS));

    /**
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfdatagetlength(_:)">developer.apple.com</a>
     */
    static long CFDataGetLength(@NotNull MemorySegment theData) {
        try {
            return (long) CFDataGetLengthHandle.invokeExact(theData);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFDataGetLength", e);
        }
    }

    /**
     * Returns a read-only pointer to the bytes of a CFData object. The pointer is valid only while the CFData
     * object is alive (Get Rule), so callers copy the bytes into a Java array right away.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cfdatagetbyteptr(_:)">developer.apple.com</a>
     */
    static MemorySegment CFDataGetBytePtr(@NotNull MemorySegment theData) {
        try {
            return (MemorySegment) CFDataGetBytePtrHandle.invokeExact(theData);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFDataGetBytePtr", e);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // CFError
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Mac OS 9/Carbon errors. Domain of the errors we synthesize from an {@code OSStatus} result code.
     *
     * @see <a href="https://developer.apple.com/documentation/foundation/nsosstatuserrordomain">developer.apple.com</a>
     */
    static final String NSOSStatusErrorDomain = "NSOSStatusErrorDomain";

    private static final MethodHandle CFErrorGetDomainHandle = LIBRARY.downcall("CFErrorGetDomain", of(ADDRESS, ADDRESS));
    private static final MethodHandle CFErrorGetCodeHandle = LIBRARY.downcall("CFErrorGetCode", of(JAVA_LONG, ADDRESS));
    private static final MethodHandle CFErrorCopyDescriptionHandle = LIBRARY.downcall("CFErrorCopyDescription", of(ADDRESS, ADDRESS));

    /**
     * Returns the error domain for a given CFError.
     *
     * @return The error domain for err (a CFString). Ownership follows the Get Rule.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cferrorgetdomain(_:)">developer.apple.com</a>
     */
    static MemorySegment CFErrorGetDomain(@NotNull MemorySegment err) {
        try {
            return (MemorySegment) CFErrorGetDomainHandle.invokeExact(err);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFErrorGetDomain", e);
        }
    }

    /**
     * Returns the error code for a given CFError.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cferrorgetcode(_:)">developer.apple.com</a>
     */
    static long CFErrorGetCode(@NotNull MemorySegment err) {
        try {
            return (long) CFErrorGetCodeHandle.invokeExact(err);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFErrorGetCode", e);
        }
    }

    /**
     * Returns a human-presentable description for a given error.
     *
     * @return A localized, human-presentable description of err (a CFString). This function never returns NULL.
     * Ownership follows the Create Rule.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/cferrorcopydescription(_:)">developer.apple.com</a>
     */
    static MemorySegment CFErrorCopyDescription(@NotNull MemorySegment err) {
        try {
            return (MemorySegment) CFErrorCopyDescriptionHandle.invokeExact(err);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CFErrorCopyDescription", e);
        }
    }

    /**
     * Unwrapped version of CFErrorRef without native references.
     */
    record Error(@NotNull String domain, long code, @NotNull String description) {
        @Override
        public @NotNull String toString() {
            return "Error{" +
                   "domain=" + domain +
                   ", code=" + code +
                   ", description='" + description + '\'' +
                   '}';
        }
    }

    // a method call (not an inline `x == null ? NULL : x`) is required for invokeExact to see a MemorySegment argument
    private static MemorySegment nullable(@Nullable MemorySegment segment) {
        return segment == null ? MemorySegment.NULL : segment;
    }
}
