package org.jetbrains.nativecerts.mac;

import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;
import com.sun.jna.ptr.PointerByReference;
import org.jetbrains.annotations.Nullable;

public class CFArrayRefByReference extends PointerByReference {
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
