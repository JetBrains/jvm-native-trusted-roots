package org.jetbrains.nativecerts.mac;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;

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

    CoreFoundation.CFArrayRef CFArrayCreate(CoreFoundation.CFAllocatorRef alloc, Pointer[] values, CoreFoundation.CFIndex numValues, Pointer callBacks);

    boolean CFEqual(CoreFoundation.CFTypeRef cf1, CoreFoundation.CFTypeRef cf2);

    CoreFoundation.CFBooleanRef kCFBooleanFalse = resolveBoolean("kCFBooleanFalse", false);
    CoreFoundation.CFBooleanRef kCFBooleanTrue = resolveBoolean("kCFBooleanTrue", true);

    private static CoreFoundation.CFBooleanRef resolveBoolean(String name, boolean expectedValue) {
        Pointer pointer = Native.getNativeLibrary(CoreFoundation.INSTANCE).getGlobalVariableAddress(name);
        CoreFoundation.CFBooleanRef cfBoolean = new CoreFoundation.CFBooleanRef(pointer.getPointer(0));
        if (cfBoolean.booleanValue() != expectedValue) {
            throw new IllegalStateException("Expected " + name + " to be " + expectedValue + ", but got " + cfBoolean.booleanValue());
        }
        return cfBoolean;
    }
}
