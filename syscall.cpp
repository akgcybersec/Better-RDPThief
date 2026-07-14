#include "syscall.h"
#include "obf.h"

extern "C" NTSTATUS SyscallTrampoline(
    ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4,
    ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8,
    ULONG_PTR a9, ULONG_PTR a10, ULONG_PTR a11);

extern "C" DWORD g_SyscallNumber = 0;
extern "C" PVOID g_pSyscallInst = NULL;

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    BOOL  resolved;
} SYSCALL_ENTRY;

static SYSCALL_ENTRY g_SsnNtClose = { 0 };
static SYSCALL_ENTRY g_SsnNtCreateFile = { 0 };
static SYSCALL_ENTRY g_SsnNtWriteFile = { 0 };

static BOOL g_SysReady = FALSE;

// pull SSN from ntdll stub: mov r10,rcx / mov eax, <ssn>
static DWORD SysExtractSsn(PVOID fn) {
    BYTE* p = (BYTE*)fn;
    DWORD i;

    for (i = 0; i < 32; i++) {
        if (p[i] == 0x4C && p[i + 1] == 0x8B && p[i + 2] == 0xD1 && p[i + 3] == 0xB8)
            return *(DWORD*)(p + i + 4);
    }

    return 0;
}

// find the syscall;ret gadget inside the stub
static PVOID SysFindSyscallInst(PVOID fn) {
    BYTE* p = (BYTE*)fn;
    DWORD i;

    for (i = 0; i < 64; i++) {
        if (p[i] == 0x0F && p[i + 1] == 0x05 && p[i + 2] == 0xC3)
            return &p[i];
    }

    return NULL;
}

static BOOL SysResolveOne(const unsigned char* encApi, size_t apiLen, SYSCALL_ENTRY* out) {
    FARPROC fn = obfResolveApi(enc_ntdll_dll, sizeof(enc_ntdll_dll), encApi, apiLen);
    if (!fn)
        return FALSE;

    out->ssn = SysExtractSsn((PVOID)fn);
    if (!out->ssn)
        return FALSE;

    if (!g_pSyscallInst)
        g_pSyscallInst = SysFindSyscallInst((PVOID)fn);

    out->resolved = (g_pSyscallInst != NULL);
    return out->resolved;
}

static NTSTATUS SysInvoke(const SYSCALL_ENTRY* entry,
    ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4,
    ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8,
    ULONG_PTR a9, ULONG_PTR a10, ULONG_PTR a11)
{
    if (!g_SysReady || !entry || !entry->resolved || !g_pSyscallInst)
        return (NTSTATUS)0xC0000001L;

    g_SyscallNumber = entry->ssn;
    return SyscallTrampoline(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

BOOL SysInit(void) {
    if (g_SysReady)
        return TRUE;

    // only what pipe client needs — keep resolver small
    if (!SysResolveOne(enc_NtCreateFile, sizeof(enc_NtCreateFile), &g_SsnNtCreateFile))
        return FALSE;
    if (!SysResolveOne(enc_NtWriteFile, sizeof(enc_NtWriteFile), &g_SsnNtWriteFile))
        return FALSE;
    if (!SysResolveOne(enc_NtClose, sizeof(enc_NtClose), &g_SsnNtClose))
        return FALSE;

    g_SysReady = TRUE;
    return TRUE;
}

void SysShutdown(void) {
    g_SysReady = FALSE;
}

NTSTATUS SysNtClose(HANDLE Handle) {
    return SysInvoke(&g_SsnNtClose,
        (ULONG_PTR)Handle, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    return SysInvoke(&g_SsnNtCreateFile,
        (ULONG_PTR)FileHandle, (ULONG_PTR)DesiredAccess, (ULONG_PTR)ObjectAttributes,
        (ULONG_PTR)IoStatusBlock, (ULONG_PTR)AllocationSize, (ULONG_PTR)FileAttributes,
        (ULONG_PTR)ShareAccess, (ULONG_PTR)CreateDisposition, (ULONG_PTR)CreateOptions,
        (ULONG_PTR)EaBuffer, (ULONG_PTR)EaLength);
}

NTSTATUS SysNtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    return SysInvoke(&g_SsnNtWriteFile,
        (ULONG_PTR)FileHandle, (ULONG_PTR)Event, (ULONG_PTR)ApcRoutine, (ULONG_PTR)ApcContext,
        (ULONG_PTR)IoStatusBlock, (ULONG_PTR)Buffer, (ULONG_PTR)Length,
        (ULONG_PTR)ByteOffset, (ULONG_PTR)Key, 0, 0);
}
