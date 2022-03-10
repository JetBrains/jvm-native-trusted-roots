package org.jetbrains.nativecerts.mac;

import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;
import com.sun.jna.ptr.PointerByReference;
import org.jetbrains.annotations.Nullable;

public class CFStringRefByReference extends PointerByReference {
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
