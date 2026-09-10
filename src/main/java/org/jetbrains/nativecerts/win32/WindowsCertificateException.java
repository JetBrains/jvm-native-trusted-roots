package org.jetbrains.nativecerts.win32;

public final class WindowsCertificateException extends IllegalStateException {
    private static final long serialVersionUID = 1L;
    private final int errorCode;

    WindowsCertificateException(String operation, int errorCode) {
        super(operation + " failed with Windows error 0x" + Integer.toHexString(errorCode));
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
