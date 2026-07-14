#include "pipe.h"
#include "config.h"

static HANDLE g_ServerPipe = INVALID_HANDLE_VALUE;

static BOOL PipeReadAll(HANDLE handle, void* data, ULONG byteLen) {
    BYTE* p = (BYTE*)data;
    ULONG got = 0;

    while (got < byteLen) {
        DWORD chunk = 0;

        if (!ReadFile(handle, p + got, byteLen - got, &chunk, NULL))
            return FALSE;
        if (chunk == 0)
            return FALSE;

        got += chunk;
    }

    return TRUE;
}

BOOL PipeServerInit(void) {
    g_ServerPipe = CreateNamedPipeW(
        PIPE_WIN32_PATH,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_OUTBOUND_QUOTA,
        PIPE_INBOUND_QUOTA,
        0,
        NULL);

    return g_ServerPipe != INVALID_HANDLE_VALUE;
}

BOOL PipeServerWaitClient(DWORD timeoutMs) {
    (void)timeoutMs;

    if (g_ServerPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    if (ConnectNamedPipe(g_ServerPipe, NULL))
        return TRUE;

    return GetLastError() == ERROR_PIPE_CONNECTED;
}

BOOL PipeServerReadMessage(WCHAR* out, ULONG outChars, ULONG* outLen) {
    ULONG payloadLen = 0;
    BYTE header[sizeof(ULONG)] = { 0 };

    if (!out || outChars < 2 || !outLen)
        return FALSE;

    if (!PipeReadAll(g_ServerPipe, header, sizeof(header)))
        return FALSE;

    payloadLen = *(ULONG*)header;
    if (payloadLen == 0 || payloadLen > PIPE_MAX_ENTRY_BYTES || (payloadLen % sizeof(WCHAR)) != 0)
        return FALSE;
    if ((payloadLen / sizeof(WCHAR)) >= outChars)
        return FALSE;

    if (!PipeReadAll(g_ServerPipe, out, payloadLen))
        return FALSE;

    out[payloadLen / sizeof(WCHAR)] = L'\0';
    *outLen = payloadLen;
    return TRUE;
}

void PipeServerDisconnect(void) {
    if (g_ServerPipe == INVALID_HANDLE_VALUE)
        return;

    FlushFileBuffers(g_ServerPipe);
    DisconnectNamedPipe(g_ServerPipe);
}
