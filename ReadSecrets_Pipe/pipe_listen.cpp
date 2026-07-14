#include <stdio.h>
#include <windows.h>
#include "config.h"
#include "pipe.h"

int wmain(void) {
    WCHAR buf[PIPE_MAX_ENTRY_BYTES / sizeof(WCHAR) + 1] = { 0 };
    ULONG len = 0;

    wprintf(L"[*] Lab pipe server listening on %s\n", PIPE_WIN32_PATH);
    wprintf(L"[*] Start this before injecting tsclient.dll into mstsc.exe.\n\n");

    if (!PipeServerInit()) {
        wprintf(L"[!] CreateNamedPipe failed (%lu)\n", GetLastError());
        return 1;
    }

    for (;;) {
        if (!PipeServerWaitClient(INFINITE)) {
            wprintf(L"[!] ConnectNamedPipe failed (%lu)\n", GetLastError());
            continue;
        }

        if (PipeServerReadMessage(buf, (ULONG)_countof(buf), &len))
            wprintf(L"%s", buf);
        else
            wprintf(L"[!] Read failed (%lu)\n", GetLastError());

        PipeServerDisconnect();
    }

    return 0;
}
