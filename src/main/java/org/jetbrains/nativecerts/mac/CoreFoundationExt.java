package org.jetbrains.nativecerts.mac;

import com.sun.jna.Library;
import com.sun.jna.Native;
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
}
