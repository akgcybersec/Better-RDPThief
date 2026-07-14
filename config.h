#pragma once

// NT path for syscall client, Win32 path for implant server
#define PIPE_NT_PATH     L"\\??\\pipe\\BetterRDPThief"
#define PIPE_WIN32_PATH  L"\\\\.\\pipe\\BetterRDPThief"
#define PIPE_MAX_ENTRY_BYTES 8192
#define PIPE_MAX_FRAME_BYTES (sizeof(ULONG) + PIPE_MAX_ENTRY_BYTES)

#define PIPE_INBOUND_QUOTA  8192
#define PIPE_OUTBOUND_QUOTA 8192
