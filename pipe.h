#pragma once

#include <windows.h>

BOOL PipeClientInit(void);
void PipeClientShutdown(void);
BOOL PipeClientSend(const WCHAR* text);
