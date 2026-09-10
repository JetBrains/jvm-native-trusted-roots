package org.jetbrains.nativecerts.win32;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.nativecerts.NativeLibrary;

import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.FunctionDescriptor.of;
import static java.lang.foreign.FunctionDescriptor.ofVoid;
import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Raw bindings to the parts of Crypt32.dll (CryptoAPI certificate store and chain functions) used by {@link Crypt32ExtUtil}.
 * <p>
 * Naming follows {@code wincrypt.h}. Handles and pointers ({@code HCERTSTORE}, {@code PCCERT_CONTEXT},
 * {@code PCCERT_CHAIN_CONTEXT}, {@code LPCSTR}, ...) are {@link MemorySegment}; {@code DWORD} and {@code BOOL} are
 * {@code int}. Structures are described in {@link WinCryptStructures}.
 * <p>
 * Functions that report failures via {@code GetLastError} are linked with {@link Linker.Option#captureCallState},
 * so the value of {@code GetLastError} right after the call is stored into a caller-provided segment of
 * {@link #CALL_STATE_LAYOUT} (first parameter of such wrappers) and can be read with {@link #getLastError}.
 * Reading it any later (e.g. via a separate downcall to {@code GetLastError}) would be unreliable because
 * the JVM itself may make Win32 calls in between.
 */
@SuppressWarnings({"SpellCheckingInspection", "unused"})
final class Crypt32Ext {
    private Crypt32Ext() {
    }

    // Store providers for CertOpenStore (passed as the low word of an LPCSTR)
    static final int CERT_STORE_PROV_MSG = 1;
    static final int CERT_STORE_PROV_MEMORY = 2;
    static final int CERT_STORE_PROV_FILE = 3;
    static final int CERT_STORE_PROV_REG = 4;
    static final int CERT_STORE_PROV_PKCS7 = 5;
    static final int CERT_STORE_PROV_SERIALIZED = 6;
    static final int CERT_STORE_PROV_FILENAME_A = 7; // ASCII
    static final int CERT_STORE_PROV_FILENAME_W = 8; // Unicode
    static final int CERT_STORE_PROV_FILENAME = CERT_STORE_PROV_FILENAME_W;
    static final int CERT_STORE_PROV_SYSTEM_A = 9; // pvPara is ASCII (1 byte/char)
    static final int CERT_STORE_PROV_SYSTEM_W = 10; // pvPara is Unicode (2 bytes/char)
    static final int CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_W;
    static final int CERT_STORE_PROV_COLLECTION = 11;
    static final int CERT_STORE_PROV_SYSTEM_REGISTRY_A = 12;
    static final int CERT_STORE_PROV_SYSTEM_REGISTRY_W = 13;
    static final int CERT_STORE_PROV_SYSTEM_REGISTRY = CERT_STORE_PROV_SYSTEM_REGISTRY_W;
    static final int CERT_STORE_PROV_PHYSICAL_W = 14;
    static final int CERT_STORE_PROV_PHYSICAL = CERT_STORE_PROV_PHYSICAL_W;
    static final int CERT_STORE_PROV_SMART_CARD_W = 15;
    static final int CERT_STORE_PROV_SMART_CARD = CERT_STORE_PROV_SMART_CARD_W;
    static final int CERT_STORE_PROV_LDAP_W = 16;
    static final int CERT_STORE_PROV_LDAP = CERT_STORE_PROV_LDAP_W;

    // Store characteristics for CertOpenStore
    static final int CERT_STORE_NO_CRYPT_RELEASE_FLAG = 0x00000001;
    static final int CERT_STORE_SET_LOCALIZED_NAME_FLAG = 0x00000002;
    static final int CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = 0x00000004;
    static final int CERT_STORE_DELETE_FLAG = 0x00000010;
    static final int CERT_STORE_UNSAFE_PHYSICAL_FLAG = 0x00000020;
    static final int CERT_STORE_SHARE_STORE_FLAG = 0x00000040;
    static final int CERT_STORE_SHARE_CONTEXT_FLAG = 0x00000080;
    static final int CERT_STORE_MANIFOLD_FLAG = 0x00000100;
    static final int CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200;
    static final int CERT_STORE_UPDATE_KEYID_FLAG = 0x00000400;
    static final int CERT_STORE_BACKUP_RESTORE_FLAG = 0x00000800;
    static final int CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000;
    static final int CERT_STORE_CREATE_NEW_FLAG = 0x00002000;
    static final int CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
    static final int CERT_STORE_READONLY_FLAG = 0x00008000;

    // Store locations for CertOpenStore
    static final int CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
    static final int CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;
    static final int CERT_SYSTEM_STORE_CURRENT_SERVICE = 0x00040000;
    static final int CERT_SYSTEM_STORE_SERVICES = 0x00050000;
    static final int CERT_SYSTEM_STORE_USERS = 0x00060000;
    static final int CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = 0x00070000;
    static final int CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = 0x00080000;
    static final int CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = 0x00090000;
    static final int CERT_SYSTEM_STORE_UNPROTECTED_FLAG = 0x40000000;
    static final int CERT_SYSTEM_STORE_RELOCATE_FLAG = 0x80000000;

    // Certificate encoding types for CertCreateCertificateContext
    static final int X509_ASN_ENCODING = 0x00000001;
    static final int PKCS_7_ASN_ENCODING = 0x00010000;

    // CERT_USAGE_MATCH.dwType for CertGetCertificateChain
    static final int USAGE_MATCH_TYPE_AND = 0x00000000;
    static final int USAGE_MATCH_TYPE_OR = 0x00000001;

    // Revocation flags for CertGetCertificateChain https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain
    static final int CERT_CHAIN_REVOCATION_CHECK_END_CERT = 0x10000000;
    static final int CERT_CHAIN_REVOCATION_CHECK_CHAIN = 0x20000000;
    static final int CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x40000000;
    static final int CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY = 0x80000000;

    // for CertVerifyCertificateChainPolicy https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy
    // (predefined policy OIDs are passed as the low word of an LPCSTR)
    static final int CERT_CHAIN_POLICY_BASE = 1;
    static final int CERT_CHAIN_POLICY_AUTHENTICODE = 2;
    static final int CERT_CHAIN_POLICY_AUTHENTICODE_TS = 3;
    static final int CERT_CHAIN_POLICY_SSL = 4;

    // Win32 error codes (winerror.h) that are handled explicitly
    /** ERROR_FILE_NOT_FOUND: returned by CertOpenStore when the store does not exist. */
    static final int ERROR_FILE_NOT_FOUND = 2;
    /** ERROR_NO_MORE_FILES: end of enumeration or a missing store. */
    static final int ERROR_NO_MORE_FILES = 18;
    /** CRYPT_E_NOT_FOUND: CertEnumCertificatesInStore has no more certificates. */
    static final int CRYPT_E_NOT_FOUND = 0x80092004;
    /**
     * CERT_E_UNTRUSTEDROOT: a certificate chain processed, but terminated in a root certificate which is not trusted
     * by the trust provider. Reported by CertVerifyCertificateChainPolicy in {@code CERT_CHAIN_POLICY_STATUS.dwError}.
     */
    static final int CERT_E_UNTRUSTEDROOT = 0x800B0109;

    // ---------------------------------------------------------------------------------------------------------------
    // GetLastError capture
    // ---------------------------------------------------------------------------------------------------------------

    private static final Linker.Option CAPTURE_LAST_ERROR = Linker.Option.captureCallState("GetLastError");

    /**
     * Layout of the segment that receives the captured {@code GetLastError} value; allocate it per call site
     * and pass it as the first argument to the wrappers below.
     */
    static final MemoryLayout CALL_STATE_LAYOUT = Linker.Option.captureStateLayout();

    private static final long GET_LAST_ERROR_OFFSET = CALL_STATE_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("GetLastError"));

    /**
     * @param callState Segment of {@link #CALL_STATE_LAYOUT} passed to the failing call
     * @return The value {@code GetLastError()} had right after that call
     */
    static int getLastError(@NotNull MemorySegment callState) {
        return callState.get(JAVA_INT, GET_LAST_ERROR_OFFSET);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Functions
    // ---------------------------------------------------------------------------------------------------------------

    private static final NativeLibrary LIBRARY = new NativeLibrary("Crypt32.dll");

    private static final MethodHandle CertOpenStoreHandle = LIBRARY.downcall("CertOpenStore",
            of(ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS), CAPTURE_LAST_ERROR);
    private static final MethodHandle CertEnumCertificatesInStoreHandle = LIBRARY.downcall("CertEnumCertificatesInStore",
            of(ADDRESS, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
    private static final MethodHandle CertCloseStoreHandle = LIBRARY.downcall("CertCloseStore",
            of(JAVA_INT, ADDRESS, JAVA_INT), CAPTURE_LAST_ERROR);
    private static final MethodHandle CertCreateCertificateContextHandle = LIBRARY.downcall("CertCreateCertificateContext",
            of(ADDRESS, JAVA_INT, ADDRESS, JAVA_INT), CAPTURE_LAST_ERROR);
    private static final MethodHandle CertFreeCertificateContextHandle = LIBRARY.downcall("CertFreeCertificateContext",
            of(JAVA_INT, ADDRESS));
    private static final MethodHandle CertGetCertificateChainHandle = LIBRARY.downcall("CertGetCertificateChain",
            of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
    private static final MethodHandle CertVerifyCertificateChainPolicyHandle = LIBRARY.downcall("CertVerifyCertificateChainPolicy",
            of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
    private static final MethodHandle CertFreeCertificateChainHandle = LIBRARY.downcall("CertFreeCertificateChain",
            ofVoid(ADDRESS));

    /**
     * The {@code CertOpenStore} function opens a certificate store by using a specified store provider type
     *
     * @param callState         Receives GetLastError, see {@link #getLastError}.
     * @param lpszStoreProvider A pointer to a null-terminated ANSI string that contains the store provider type,
     *                          or one of the predefined {@code CERT_STORE_PROV_*} integer constants cast to a pointer
     *                          ({@code MemorySegment.ofAddress(CERT_STORE_PROV_SYSTEM_REGISTRY_W)}).
     * @param dwEncodingType    Specifies the <a href="https://docs.microsoft.com/en-us/windows/desktop/SecGloss/c-gly">certificate encoding type</a>
     *                          and <a href="https://docs.microsoft.com/en-us/windows/desktop/SecGloss/m-gly">message encoding</a> type.
     *                          Encoding is used only when the {@code dwSaveAs} parameter of the
     *                          <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certsavestore">CertSaveStore</a>
     *                          function contains {@code CERT_STORE_SAVE_AS_PKCS7}.
     *                          Otherwise, the {@code dwMsgAndCertEncodingType} parameter is not used.
     * @param hCryptProv        This parameter is not used and should be set to NULL.
     * @param dwFlags           These values consist of high-word and low-word values combined by using a bitwise-OR operation.
     *                          See {@code CERT_STORE_*_FLAG} and {@code CERT_SYSTEM_STORE_*} constants.
     * @param pvPara            A value that can contain additional information for this function. The contents of
     *                          this parameter depends on the value of the {@code lpszStoreProvider} and other parameters.
     *                          For {@code CERT_STORE_PROV_SYSTEM_REGISTRY_W} it is a NUL-terminated UTF-16 store name ("ROOT", "CA").
     * @return If the function succeeds, the function returns a handle to the certificate store.
     * When you have finished using the store, release the handle by calling the {@link #CertCloseStore} function.
     * If the function fails, it returns NULL. For extended error information, call {@link #getLastError}.
     * @see <a href="https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore">MSDN</a>
     */
    static MemorySegment CertOpenStore(@NotNull MemorySegment callState,
                                       @NotNull MemorySegment lpszStoreProvider,
                                       int dwEncodingType,
                                       @Nullable MemorySegment hCryptProv,
                                       int dwFlags,
                                       @NotNull MemorySegment pvPara) {
        try {
            return (MemorySegment) CertOpenStoreHandle.invokeExact(callState, lpszStoreProvider, dwEncodingType, nullable(hCryptProv), dwFlags, pvPara);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertOpenStore", e);
        }
    }

    /**
     * The {@code CertEnumCertificatesInStore} function retrieves the first or next certificate in a certificate store.
     * Used in a loop, this function can retrieve in sequence all certificates in a certificate store.
     *
     * @param callState        Receives GetLastError, see {@link #getLastError}.
     * @param hCertStore       A handle of a certificate store.
     * @param pPrevCertContext A pointer to the {@code CERT_CONTEXT} of the previous certificate context found.
     *                         This parameter must be NULL to begin the enumeration and get the first certificate in the store.
     *                         Successive certificates are enumerated by setting {@code pPrevCertContext} to the pointer
     *                         returned by a previous call to the function. <b>This function frees the CERT_CONTEXT
     *                         referenced by non-NULL values of this parameter.</b>
     * @return If the function succeeds, the function returns a pointer to the next {@code CERT_CONTEXT} in the store
     * (see {@link WinCryptStructures#CERT_CONTEXT}). If no more certificates exist in the store, or on failure,
     * NULL is returned and {@link #getLastError} is {@link #CRYPT_E_NOT_FOUND} (end of enumeration) or
     * {@link #ERROR_NO_MORE_FILES} (store is empty).
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore">MSDN</a>
     */
    static MemorySegment CertEnumCertificatesInStore(@NotNull MemorySegment callState,
                                                     @NotNull MemorySegment hCertStore,
                                                     @Nullable MemorySegment pPrevCertContext) {
        try {
            return (MemorySegment) CertEnumCertificatesInStoreHandle.invokeExact(callState, hCertStore, nullable(pPrevCertContext));
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertEnumCertificatesInStore", e);
        }
    }

    /**
     * The {@code CertCloseStore} function closes a certificate store handle and reduces the reference count on the store.
     *
     * @param callState  Receives GetLastError, see {@link #getLastError}.
     * @param hCertStore Handle of the certificate store to be closed.
     * @param dwFlags    Typically set to zero. {@code CERT_CLOSE_STORE_CHECK_FLAG} / {@code CERT_CLOSE_STORE_FORCE_FLAG} are possible.
     * @return If the function succeeds, the return value is TRUE (non-zero). If the function fails, the return value is FALSE (zero).
     * For extended error information, call {@link #getLastError}.
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certclosestore">MSDN</a>
     */
    static boolean CertCloseStore(@NotNull MemorySegment callState, @NotNull MemorySegment hCertStore, int dwFlags) {
        try {
            return (int) CertCloseStoreHandle.invokeExact(callState, hCertStore, dwFlags) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertCloseStore", e);
        }
    }

    /**
     * The {@code CertCreateCertificateContext} function creates a certificate context from an encoded certificate.
     * The created context is not persisted to a certificate store.
     * The function makes a copy of the encoded certificate within the created context.
     *
     * @param callState          Receives GetLastError, see {@link #getLastError}.
     * @param dwCertEncodingType [in] Specifies the type of encoding used. It is always acceptable to specify both the certificate and message
     *                           encoding types by combining them with a bitwise-OR operation as shown in the following example:
     *                           X509_ASN_ENCODING | PKCS_7_ASN_ENCODING. Currently, defined encoding types are:
     *                           {@link #X509_ASN_ENCODING} {@link #PKCS_7_ASN_ENCODING}
     * @param pbCertEncoded      [in] A pointer to a buffer that contains the encoded certificate from which the context is to be created.
     * @param cbCertEncoded      [in] The size, in bytes, of the {@code pbCertEncoded} buffer.
     * @return If the function succeeds, the function returns a pointer to a read-only {@code CERT_CONTEXT}.
     * When you have finished using the certificate context, free it by calling the {@link #CertFreeCertificateContext} function.
     * If the function is unable to decode and create the certificate context, it returns NULL.
     * For extended error information, call {@link #getLastError}.
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certcreatecertificatecontext">MSDN</a>
     */
    static MemorySegment CertCreateCertificateContext(@NotNull MemorySegment callState,
                                                      int dwCertEncodingType,
                                                      @NotNull MemorySegment pbCertEncoded,
                                                      int cbCertEncoded) {
        try {
            return (MemorySegment) CertCreateCertificateContextHandle.invokeExact(callState, dwCertEncodingType, pbCertEncoded, cbCertEncoded);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertCreateCertificateContext", e);
        }
    }

    /**
     * The {@code CertFreeCertificateContext} function frees a certificate context by decrementing its reference count.
     * When the reference count goes to zero, {@code CertFreeCertificateContext} frees the memory used by a certificate context.
     *
     * @param pCertContext A pointer to the {@code CERT_CONTEXT} to be freed.
     * @return The function always returns TRUE.
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatecontext">MSDN</a>
     */
    static boolean CertFreeCertificateContext(@NotNull MemorySegment pCertContext) {
        try {
            return (int) CertFreeCertificateContextHandle.invokeExact(pCertContext) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertFreeCertificateContext", e);
        }
    }

    /**
     * The {@code CertGetCertificateChain} function builds a certificate chain context starting from an end certificate
     * and going back, if possible, to a trusted root certificate.
     *
     * @param callState        Receives GetLastError, see {@link #getLastError}.
     * @param hChainEngine     A handle of the chain engine (namespace and cache) to be used. NULL uses the default chain
     *                         engine, {@code HCCE_CURRENT_USER}.
     * @param pCertContext     A pointer to the {@code CERT_CONTEXT} of the end certificate, the certificate for which
     *                         a chain is being built. This certificate context will be the zero-index element in the
     *                         first simple chain.
     * @param pTime            A pointer to a {@code FILETIME} variable that indicates the time for which the chain is
     *                         to be validated. NULL uses the current system time.
     * @param hAdditionalStore A handle of any additional store to search for supporting certificates and certificate
     *                         trust lists (CTLs). This parameter can be NULL if no additional store is to be searched.
     * @param pChainPara       A pointer to a {@code CERT_CHAIN_PARA} structure that includes chain-building parameters,
     *                         see {@link WinCryptStructures#CERT_CHAIN_PARA}.
     * @param dwFlags          Flag values that indicate special processing, see {@code CERT_CHAIN_REVOCATION_*}.
     * @param pvReserved       This parameter is reserved and must be NULL.
     * @param ppChainContext   The address of a pointer to the chain context created. When you have finished using the
     *                         chain context, release the chain by calling the {@link #CertFreeCertificateChain} function.
     * @return If the function succeeds, the function returns nonzero (TRUE). If the function fails, it returns zero (FALSE).
     * For extended error information, call {@link #getLastError}.
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain">MSDN</a>
     */
    static boolean CertGetCertificateChain(@NotNull MemorySegment callState,
                                           @Nullable MemorySegment hChainEngine,
                                           @NotNull MemorySegment pCertContext,
                                           @Nullable MemorySegment pTime,
                                           @Nullable MemorySegment hAdditionalStore,
                                           @NotNull MemorySegment pChainPara,
                                           int dwFlags,
                                           @Nullable MemorySegment pvReserved,
                                           @NotNull MemorySegment ppChainContext) {
        try {
            return (int) CertGetCertificateChainHandle.invokeExact(callState, nullable(hChainEngine), pCertContext, nullable(pTime),
                    nullable(hAdditionalStore), pChainPara, dwFlags, nullable(pvReserved), ppChainContext) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertGetCertificateChain", e);
        }
    }

    /**
     * The {@code CertVerifyCertificateChainPolicy} function checks a certificate chain to verify its validity,
     * including its compliance with any specified validity policy criteria.
     *
     * @param callState     Receives GetLastError, see {@link #getLastError}.
     * @param pszPolicyOID  Current predefined verify chain policy structures are listed in {@code CERT_CHAIN_POLICY_*}
     *                      constants; pass them as {@code MemorySegment.ofAddress(CERT_CHAIN_POLICY_SSL)}.
     * @param pChainContext A pointer to a {@code CERT_CHAIN_CONTEXT} structure that contains a chain to be verified.
     * @param pPolicyPara   A pointer to a {@code CERT_CHAIN_POLICY_PARA} structure that provides the policy verification
     *                      criteria for the chain, see {@link WinCryptStructures#CERT_CHAIN_POLICY_PARA}.
     * @param pPolicyStatus A pointer to a {@code CERT_CHAIN_POLICY_STATUS} structure where status information on the
     *                      chain is returned, see {@link WinCryptStructures#CERT_CHAIN_POLICY_STATUS}.
     * @return The return value indicates whether the function was able to check for the policy, it does not indicate
     * whether the policy check failed or passed. If the chain could be verified, the return value is TRUE and
     * {@code pPolicyStatus->dwError} holds the verification result (0 for a valid chain).
     * If the function is unable to perform the verification, FALSE is returned; call {@link #getLastError}.
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy">MSDN</a>
     */
    static boolean CertVerifyCertificateChainPolicy(@NotNull MemorySegment callState,
                                                    @NotNull MemorySegment pszPolicyOID,
                                                    @NotNull MemorySegment pChainContext,
                                                    @NotNull MemorySegment pPolicyPara,
                                                    @NotNull MemorySegment pPolicyStatus) {
        try {
            return (int) CertVerifyCertificateChainPolicyHandle.invokeExact(callState, pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus) != 0;
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertVerifyCertificateChainPolicy", e);
        }
    }

    /**
     * The {@code CertFreeCertificateChain} function frees a certificate chain by reducing its reference count.
     * When the reference count becomes zero, memory allocated for the chain is released.
     *
     * @param pChainContext A pointer to a {@code CERT_CHAIN_CONTEXT} certificate chain context to be freed.
     * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatechain">MSDN</a>
     */
    static void CertFreeCertificateChain(@NotNull MemorySegment pChainContext) {
        try {
            CertFreeCertificateChainHandle.invokeExact(pChainContext);
        } catch (Throwable e) {
            throw NativeLibrary.rethrow("CertFreeCertificateChain", e);
        }
    }

    private static MemorySegment nullable(@Nullable MemorySegment segment) {
        return segment == null ? NULL : segment;
    }
}
