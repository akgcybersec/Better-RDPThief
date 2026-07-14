#include "obf.h"

// rolling sub per byte index — not xor, scanners hate xor loops
static const unsigned char DEC_KEY[] = {
	0x4A, 0x91, 0x2C, 0xF7, 0x63, 0xB8, 0x1E, 0xD5
};

static unsigned char obfSubByte(unsigned char enc, size_t idx) {
	unsigned char k = DEC_KEY[idx % (sizeof(DEC_KEY))];
	return (unsigned char)((enc + 256 - k) % 256);
}

void obfDecodeA(char* out, const unsigned char* enc, size_t len) {
	size_t i;

	if (!out || !enc || len == 0)
		return;

	for (i = 0; i < len; i++)
		out[i] = (char)obfSubByte(enc[i], i);
}

void obfDecodeW(wchar_t* out, const unsigned char* enc, size_t len) {
	size_t i;
	size_t outIdx = 0;

	if (!out || !enc || len < 2)
		return;

	for (i = 0; i + 1 < len; i += 2) {
		unsigned char lo = obfSubByte(enc[i], i);
		unsigned char hi = obfSubByte(enc[i + 1], i + 1);
		out[outIdx++] = (wchar_t)(lo | (hi << 8));
	}
}

void obfZero(void* buf, size_t len) {
	unsigned char* p = (unsigned char*)buf;
	size_t i;

	if (!p)
		return;

	for (i = 0; i < len; i++)
		p[i] = 0;
}

// decode dll+api name on stack, resolve, wipe stack buffers
FARPROC obfResolveApi(const unsigned char* encMod, size_t modLen, const unsigned char* encApi, size_t apiLen) {
	char modName[64] = { 0 };
	char apiName[64] = { 0 };
	HMODULE module = NULL;
	FARPROC proc = NULL;

	obfDecodeA(modName, encMod, modLen);
	obfDecodeA(apiName, encApi, apiLen);

	module = GetModuleHandleA(modName);
	if (!module)
		module = LoadLibraryA(modName);
	if (module)
		proc = GetProcAddress(module, apiName);

	obfZero(modName, sizeof(modName));
	obfZero(apiName, sizeof(apiName));
	return proc;
}
