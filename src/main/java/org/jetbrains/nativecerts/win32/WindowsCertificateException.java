package org.jetbrains.nativecerts.win32;

import org.jetbrains.annotations.NotNull;

/**
 * A CryptoAPI call failed. Replaces JNA's {@code Win32Exception}: carries the Win32 error code / HRESULT
 * (from {@code GetLastError} or from {@code CERT_CHAIN_POLICY_STATUS.dwError}) and the system message text for it.
 */
public final class WindowsCertificateException extends IllegalStateException {
    private static final long serialVersionUID = 1L;
    private final int errorCode;

    /**
     * @param operation Name of the failed native function, e.g. {@code CertOpenStore}
     * @param errorCode Win32 error code or HRESULT, see {@code Crypt32Ext.ERROR_*}/{@code CERT_E_*} constants
     */
    WindowsCertificateException(@NotNull String operation, int errorCode) {
        super(operation + " failed with error 0x" + Integer.toHexString(errorCode) + ": " + describe(errorCode));
        this.errorCode = errorCode;
    }

    /**
     * @return Win32 error code or HRESULT, e.g. {@code Crypt32Ext.CERT_E_UNTRUSTEDROOT}
     */
    public int getErrorCode() {
        return errorCode;
    }

    private static String describe(int errorCode) {
        try {
            String message = Kernel32Ext.formatMessage(errorCode);
            return message == null ? "<no system message>" : message;
        } catch (Throwable t) {
            // never let diagnostics hide the original failure
            return "<unable to format message: " + t + ">";
        }
    }
}
