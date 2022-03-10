package org.jetbrains.nativecerts.win32;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WTypes;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

@SuppressWarnings({"SpellCheckingInspection", "unused"})
public interface Crypt32Ext extends StdCallLibrary {
    // Store providers for CertOpenStore
    int CERT_STORE_PROV_MSG = 1;
    int CERT_STORE_PROV_MEMORY  = 2;
    int CERT_STORE_PROV_FILE = 3;
    int CERT_STORE_PROV_REG  = 4;
    int CERT_STORE_PROV_PKCS7 = 5;
    int CERT_STORE_PROV_SERIALIZED = 6;
    int CERT_STORE_PROV_FILENAME_A = 7; // ASCII
    int CERT_STORE_PROV_FILENAME_W = 8; // Unicode
    int CERT_STORE_PROV_FILENAME = CERT_STORE_PROV_FILENAME_W;
    int CERT_STORE_PROV_SYSTEM_A  = 9; // pvPara is ASCII (1 byte/char)
    int CERT_STORE_PROV_SYSTEM_W  = 10; // pvPara is Unicode (2 bytes/char)
    int CERT_STORE_PROV_SYSTEM  = CERT_STORE_PROV_SYSTEM_W;
    int CERT_STORE_PROV_COLLECTION  = 11;
    int CERT_STORE_PROV_SYSTEM_REGISTRY_A = 12;
    int CERT_STORE_PROV_SYSTEM_REGISTRY_W = 13;
    int CERT_STORE_PROV_SYSTEM_REGISTRY = CERT_STORE_PROV_SYSTEM_REGISTRY_W;
    int CERT_STORE_PROV_PHYSICAL_W = 14;
    int CERT_STORE_PROV_PHYSICAL = CERT_STORE_PROV_PHYSICAL_W;
    int CERT_STORE_PROV_SMART_CARD_W  = 15;
    int CERT_STORE_PROV_SMART_CARD = CERT_STORE_PROV_SMART_CARD_W;
    int CERT_STORE_PROV_LDAP_W  = 16;
    int CERT_STORE_PROV_LDAP = CERT_STORE_PROV_LDAP_W;

    // Store characteristics for CertOpenStore
    int CERT_STORE_NO_CRYPT_RELEASE_FLAG = 0x00000001;
    int CERT_STORE_SET_LOCALIZED_NAME_FLAG = 0x00000002;
    int CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = 0x00000004;
    int CERT_STORE_DELETE_FLAG = 0x00000010;
    int CERT_STORE_UNSAFE_PHYSICAL_FLAG = 0x00000020;
    int CERT_STORE_SHARE_STORE_FLAG = 0x00000040;
    int CERT_STORE_SHARE_CONTEXT_FLAG = 0x00000080;
    int CERT_STORE_MANIFOLD_FLAG = 0x00000100;
    int CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200;
    int CERT_STORE_UPDATE_KEYID_FLAG = 0x00000400;
    int CERT_STORE_BACKUP_RESTORE_FLAG = 0x00000800;
    int CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000;
    int CERT_STORE_CREATE_NEW_FLAG = 0x00002000;
    int CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
    int CERT_STORE_READONLY_FLAG = 0x00008000;

    // Store locations for CertOpenStore
    int CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
    int CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;
    int CERT_SYSTEM_STORE_CURRENT_SERVICE = 0x00040000;
    int CERT_SYSTEM_STORE_SERVICES = 0x00050000;
    int CERT_SYSTEM_STORE_USERS = 0x00060000;
    int CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = 0x00070000;
    int CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = 0x00080000;
    int CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = 0x00090000;
    int CERT_SYSTEM_STORE_UNPROTECTED_FLAG = 0x40000000;
    int CERT_SYSTEM_STORE_RELOCATE_FLAG = 0x80000000;

    // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencodeobjectex
    int X509_ASN_ENCODING = 1;
    int PKCS_7_ASN_ENCODING = 0x10000;

    Crypt32Ext INSTANCE = Native.load("Crypt32", Crypt32Ext.class, W32APIOptions.DEFAULT_OPTIONS);

    /**
     * The {@code CertOpenStore} function opens a certificate store by using a specified store provider type
     *
     * @param lpszStoreProvider
     *          A pointer to a null-terminated ANSI string that contains the store provider type.
     * @param dwEncodingType
     *          Specifies the <a href="https://docs.microsoft.com/en-us/windows/desktop/SecGloss/c-gly">certificate encoding type</a>
     *          and <a href="https://docs.microsoft.com/en-us/windows/desktop/SecGloss/m-gly">message encoding</a> type.
     *          Encoding is used only when the {@code dwSaveAs} parameter of the
     *          <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certsavestore">CertSaveStore</a>
     *          function contains {@code CERT_STORE_SAVE_AS_PKCS7}.
     *          Otherwise, the {@code dwMsgAndCertEncodingType} parameter is not used.
     * @param hCryptProv
     *          This parameter is not used and should be set to NULL.
     * @param dwFlags
     *          These values consist of high-word and low-word values combined by using a bitwise-OR operation.
     *          See {@code CERT_STORE_*_FLAG} and {@code CERT_SYSTEM_STORE_*} constants.
     * @param pvPara
     *          A 32-bit value that can contain additional information for this function. The contents of
     *          this parameter depends on the value of the {@code lpszStoreProvider} and other parameters.
     * @return
     *          If the function succeeds, the function returns a handle to the certificate store.
     *          When you have finished using the store, release the handle by calling the
     *          {@link com.sun.jna.platform.win32.Crypt32#CertCloseStore(WinCrypt.HCERTSTORE, int)} function.
     *          If the function fails, it returns NULL. For extended error information,
     *          call {@link Native#getLastError()}.
     *
     * @see <a href="https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore">MSDN</a>
     */
    WinCrypt.HCERTSTORE CertOpenStore(
            WTypes.LPSTR lpszStoreProvider,
            int dwEncodingType,
            WinCrypt.HCRYPTPROV_LEGACY hCryptProv,
            int dwFlags,
            Pointer pvPara);
}
