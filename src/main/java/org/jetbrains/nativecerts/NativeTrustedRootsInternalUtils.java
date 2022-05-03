package org.jetbrains.nativecerts;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Locale;

@ApiStatus.Internal
public class NativeTrustedRootsInternalUtils {
    private static final String _OS_NAME = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
    public static final boolean isWindows = _OS_NAME.startsWith("windows");
    public static final boolean isMac = _OS_NAME.startsWith("mac");
    public static final boolean isLinux = _OS_NAME.startsWith("linux");

    public static String renderExceptionMessage(@NotNull String message, @NotNull Throwable exception) {
        StringWriter throwableText = new StringWriter();
        exception.printStackTrace(new PrintWriter(throwableText));
        return message + ": " + exception.getMessage() + "\n" + throwableText;
    }
}
