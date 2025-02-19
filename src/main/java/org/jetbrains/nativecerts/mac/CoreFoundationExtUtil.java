package org.jetbrains.nativecerts.mac;

import com.sun.jna.platform.mac.CoreFoundation;
import com.sun.jna.platform.mac.CoreFoundation.CFTypeRef;

import java.util.Map;

public class CoreFoundationExtUtil {
    private CoreFoundationExtUtil() {
    }

    public static CoreFoundation.CFDictionaryRef createDictionary(Map<CFTypeRef, CFTypeRef> map) {
        int mapSize = map.size();

        CFTypeRef[] keys = new CFTypeRef[mapSize];
        CFTypeRef[] values = new CFTypeRef[mapSize];

        int i = 0;
        for (Map.Entry<CFTypeRef, CFTypeRef> entry : map.entrySet()) {
            keys[i] = entry.getKey();
            values[i] = entry.getValue();
            i++;
        }

        return CoreFoundationExt.INSTANCE.CFDictionaryCreate(
                null,
                keys, values, new CoreFoundation.CFIndex(mapSize), null, null);
    }
}
