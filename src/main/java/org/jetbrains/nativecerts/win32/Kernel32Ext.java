package org.jetbrains.nativecerts.win32;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeLibrary;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Raw bindings to the part of Kernel32.dll used to render Win32 error codes as text (formerly JNA's {@code Kernel32Util.formatMessage}).
 */
@SuppressWarnings("SpellCheckingInspection")
final class Kernel32Ext {
    private Kernel32Ext() {
    }

    // Flags for FormatMessage
    /** The function should search the system message-table resource(s) for the requested message. */
    static final int FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
    /** Insert sequences in the message definition such as %1 are to be ignored and passed through to the output buffer unchanged. */
    static final int FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;

    private static final NativeLibrary LIBRARY = new NativeLibrary("Kernel32.dll");

    private static final MethodHandle FormatMessageWHandle = LIBRARY.downcall("FormatMessageW",
            of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));

    /**
     * Formats a message string. The function requires a message definition as input. The message definition can come
     * from a buffer passed into the function. It can come from a message table resource in an already-loaded module.
     * Or the caller can ask the function to search the system's message table resource(s) for the message definition.
     *
     * @param dwFlags      The formatting options, and how to interpret the {@code lpSource} parameter,
     *                     see {@code FORMAT_MESSAGE_*}.
     * @param lpSource     The location of the message definition. NULL with {@link #FORMAT_MESSAGE_FROM_SYSTEM}.
     * @param dwMessageId  The message identifier for the requested message (a Win32 error code or an HRESULT).
     * @param dwLanguageId The language identifier for the requested message. 0 selects the default order of languages
     *                     (thread, user, system, US English).
     * @param lpBuffer     A pointer to a buffer that receives the null-terminated string that specifies the formatted message.
     * @param nSize        The size of the output buffer, in TCHARs (UTF-16 code units).
     * @param arguments    An array of values that are used as insert values in the formatted message. NULL with
     *                     {@link #FORMAT_MESSAGE_IGNORE_INSERTS}.
     * @return If the function succeeds, the return value is the number of TCHARs stored in the output buffer,
     * excluding the terminating null character. If the function fails, the return value is zero.
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew">MSDN</a>
     */
    static int FormatMessageW(int dwFlags,
                              @Nullable MemorySegment lpSource,
                              int dwMessageId,
                              int dwLanguageId,
                              @NotNull MemorySegment lpBuffer,
                              int nSize,
                              @Nullable MemorySegment arguments) {
        try {
            return (int) FormatMessageWHandle.invokeExact(dwFlags, nullable(lpSource), dwMessageId, dwLanguageId,
                    lpBuffer, nSize, nullable(arguments));
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("FormatMessageW", e);
        }
    }

    /**
     * System message text for a Win32 error code or HRESULT, e.g. "A certificate chain processed, but terminated in a
     * root certificate which is not trusted by the trust provider." Trailing line breaks are removed.
     *
     * @return null if Windows has no message for the code
     */
    static @Nullable String formatMessage(int errorCode) {
        int bufferLength = 4096;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buffer = arena.allocate(JAVA_CHAR, bufferLength);
            int length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, null, errorCode, 0,
                    buffer, bufferLength, null);
            if (length <= 0) {
                return null;
            }
            // read the NUL-terminated string; `length` excludes the terminator, so do not slice the buffer to it
            String message = buffer.getString(0, StandardCharsets.UTF_16LE);
            return message.strip();
        }
    }

    private static MemorySegment nullable(@Nullable MemorySegment segment) {
        return segment == null ? NULL : segment;
    }
}
