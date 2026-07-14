#pragma once

#include <windows.h>

BOOL PipeServerInit(void);
BOOL PipeServerWaitClient(DWORD timeoutMs);
BOOL PipeServerReadMessage(WCHAR* out, ULONG outChars, ULONG* outLen);
void PipeServerDisconnect(void);
