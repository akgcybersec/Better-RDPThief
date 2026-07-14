#pragma once

#include <windows.h>

void obfDecodeA(char* out, const unsigned char* enc, size_t len);
void obfDecodeW(wchar_t* out, const unsigned char* enc, size_t len);
void obfZero(void* buf, size_t len);
FARPROC obfResolveApi(const unsigned char* encMod, size_t modLen, const unsigned char* encApi, size_t apiLen);

#include "obf_enc.h"
