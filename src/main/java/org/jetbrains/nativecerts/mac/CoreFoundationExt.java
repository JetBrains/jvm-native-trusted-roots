package org.jetbrains.nativecerts.mac;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;
import com.sun.jna.ptr.PointerByReference;
import org.jetbrains.annotations.Nullable;

@SuppressWarnings("unused")
public interface CoreFoundationExt extends Library {
    CoreFoundationExt INSTANCE = Native.load("CoreFoundation", CoreFoundationExt.class);

    /**
     * Returns the number of key-value pairs in a dictionary.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/1516741-cfdictionarygetcount">https://developer.apple.com/documentation/corefoundation/1516741-cfdictionarygetcount</a>
     * @param theDict The dictionary to examine.
     * @return The number of key-value pairs in theDict.
     */
    CoreFoundation.CFIndex CFDictionaryGetCount(CoreFoundation.CFDictionaryRef theDict);

    /**
     * Creates an immutable dictionary containing the specified key-value pairs.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/1516782-cfdictionarycreate">https://developer.apple.com/documentation/corefoundation/1516782-cfdictionarycreate</a>
     * @return A new dictionary, or NULL if there was a problem creating the object.
     * Ownership follows the <a href="https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFMemoryMgmt/Concepts/Ownership.html">Create Rule</a>.
     */
    CoreFoundation.CFDictionaryRef CFDictionaryCreate(
            CoreFoundation.CFAllocatorRef allocator,
            CoreFoundation.CFTypeRef[] keys,
            CoreFoundation.CFTypeRef[] values,
            CoreFoundation.CFIndex numValues,
            Pointer keyCallBacks,
            Pointer valueCallBacks
    );

    /**
     * Creates a new immutable array with the given values.
     * <p>
     * This reference must be released with {@link CoreFoundation#CFRelease} to avoid leaking
     * references.
     * <p>
     * This is like {@link CoreFoundation#CFArrayCreate(CoreFoundation.CFAllocatorRef, Pointer, CoreFoundation.CFIndex, Pointer)}
     * but it takes a {@code Pointer[]} instead.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/1388741-cfarraycreate">https://developer.apple.com/documentation/corefoundation/1388741-cfarraycreate</a>
     *
     * @param alloc
     *            The allocator to use to allocate memory for the new array and its
     *            storage for values. Pass {@code null} or
     *            {@code kCFAllocatorDefault} to use the current default allocator.
     * @param values
     *            A C array of the pointer-sized values to be in the new array. The
     *            values in the new array are ordered in the same order in which
     *            they appear in this C array. This value may be {@code null} if
     *            {@code numValues} is 0. This C array is not changed or freed by
     *            this function. If {@code values} is not a valid pointer to a C
     *            array of at least {@code numValues} elements, the behavior is
     *            undefined.
     * @param numValues
     *            The number of values to copy from the {@code values} C array into
     *            the new array. This number will be the count of the new array—it
     *            must not be negative or greater than the number of elements in
     *            values.
     * @param callBacks
     *            A pointer to a {@code CFArrayCallBacks} structure initialized with
     *            the callbacks for the array to use on each value in the
     *            collection. The retain callback is used within this function, for
     *            example, to retain all of the new values from the {@code values} C
     *            array. A copy of the contents of the callbacks structure is made,
     *            so that a pointer to a structure on the stack can be passed in or
     *            can be reused for multiple collection creations.
     *            <p>
     *            This value may be {@code null}, which is treated as if a valid
     *            structure of version 0 with all fields {@code null} had been
     *            passed in.
     * @return A new immutable array containing {@code numValues} from
     *         {@code values}, or {@code null} if there was a problem creating the
     *         object.
     */
    CoreFoundation.CFArrayRef CFArrayCreate(CoreFoundation.CFAllocatorRef alloc, Pointer[] values, CoreFoundation.CFIndex numValues, Pointer callBacks);

    /**
     * Determines whether two Core Foundation objects are considered equal.
     *
     * @see <a href="https://developer.apple.com/documentation/corefoundation/1521287-cfequal">https://developer.apple.com/documentation/corefoundation/1521287-cfequal</a>
     * @param cf1 A CFType object to compare to cf2.
     * @param cf2 A CFType object to compare to cf1.
     * @return true if cf1 and cf2 are of the same type and considered equal, otherwise false.
     */
    boolean CFEqual(CoreFoundation.CFTypeRef cf1, CoreFoundation.CFTypeRef cf2);

    /**
     * Boolean false value.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/kcfbooleanfalse">https://developer.apple.com/documentation/corefoundation/kcfbooleanfalse</a>
     */
    CoreFoundation.CFBooleanRef kCFBooleanFalse = resolveBoolean("kCFBooleanFalse", false);

    /**
     * Boolean true value.
     * @see <a href="https://developer.apple.com/documentation/corefoundation/kcfbooleantrue">https://developer.apple.com/documentation/corefoundation/kcfbooleantrue</a>
     */
    CoreFoundation.CFBooleanRef kCFBooleanTrue = resolveBoolean("kCFBooleanTrue", true);

    private static CoreFoundation.CFBooleanRef resolveBoolean(String name, boolean expectedValue) {
        Pointer pointer = Native.getNativeLibrary(CoreFoundation.INSTANCE).getGlobalVariableAddress(name);
        CoreFoundation.CFBooleanRef cfBoolean = new CoreFoundation.CFBooleanRef(pointer.getPointer(0));
        if (cfBoolean.booleanValue() != expectedValue) {
            throw new IllegalStateException("Expected " + name + " to be " + expectedValue + ", but got " + cfBoolean.booleanValue());
        }
        return cfBoolean;
    }

    class CFArrayRefByReference extends PointerByReference {
        public CFArrayRefByReference() {
        }

        public CFArrayRefByReference(CoreFoundation.CFArrayRef value) {
            super(value.getPointer());
        }

        @Nullable
        public CoreFoundation.CFArrayRef getArray() {
            Pointer value = super.getValue();
            if (value == null) {
                return null;
            }

            return new CoreFoundation.CFArrayRef(value);
        }
    }

    class CFStringRefByReference extends PointerByReference {
        public CFStringRefByReference() {
        }

        public CFStringRefByReference(CoreFoundation.CFStringRef value) {
            super(value.getPointer());
        }

        @Nullable
        public CoreFoundation.CFStringRef getStringRef() {
            Pointer value = super.getValue();
            if (value == null) {
                return null;
            }

            return new CoreFoundation.CFStringRef(value);
        }
    }
}
