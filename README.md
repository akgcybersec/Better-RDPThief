# Better-RDPThief

---

## Legal Disclaimer

> **This tool is provided for authorized security research, penetration testing, and educational purposes only.**
>
> Use of this software against systems you do not own or have explicit written permission to test is **illegal** and may violate computer fraud laws including (but not limited to) the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation in your jurisdiction.
>
> The author(s) of this project **accept no liability** for any damage, data loss, legal consequences, or misuse arising from the use or misuse of this tool. You are solely responsible for ensuring that your use complies with all applicable local, state, national, and international laws and regulations.
>
> **By using this software you confirm that you have obtained all necessary authorizations and that you accept full responsibility for your actions.**

---

## What it does

`tsclient.dll` is an in-process credential harvester that targets **mstsc.exe** (Windows Remote Desktop Client). When injected it hooks three credential-handling APIs via Microsoft Detours, intercepts plaintext usernames and passwords during RDP authentication, and sends them to a **named pipe** on localhost.

Nothing is written to disk from inside mstsc. Credentials go out over `\\.\pipe\BetterRDPThief` using direct NT syscalls.

On an engagement, your **in-memory implant** hosts the pipe server and exfils captures to C2.

---

## Architecture

```
mstsc.exe ──[tsclient.dll]──► \\.\pipe\BetterRDPThief ──► implant (in memory) ──► C2
              pipe CLIENT          localhost only           pipe SERVER
```

| Role | Where it runs | How it talks |
|---|---|---|
| **Client** | `tsclient.dll` inside mstsc | `NtCreateFile` → `NtWriteFile` → `NtClose` per capture |
| **Server** | Your implant | `CreateNamedPipe` → `ConnectNamedPipe` → `ReadFile` |

The DLL is always the client. Your agent is always the server.

---

## How it works

### Named pipe exfiltration

On each capture the DLL:

1. Opens the pipe (`NtCreateFile` on `\\??\pipe\BetterRDPThief`)
2. Writes one length-prefixed UTF-16 frame (`NtWriteFile`)
3. Closes the handle (`NtClose`)

No persistent connection — connect, write, disconnect. If the implant isn't listening yet, the client retries briefly on `STATUS_PIPE_BUSY`.

**Wire format:** `[ULONG byteLen][UTF-16 payload]`

### Direct syscalls (Hell's Gate)

Only three syscalls are resolved — the minimum for pipe client I/O:

- `NtCreateFile`
- `NtWriteFile`
- `NtClose`

SSNs are parsed from clean `ntdll` stubs at runtime. API names are rolling-ADD encoded in `obf_enc.h`.

### Hooking (Microsoft Detours)

On `DLL_PROCESS_ATTACH`, `ClientInit()` resolves target APIs at runtime via `obfResolveApi()`, then attaches detours:

| Hooked API | DLL | What is captured |
|---|---|---|
| `CredReadW` | `advapi32.dll` | Target, username, password from saved credentials |
| `CredUIParseUserNameW` | `credui.dll` | Username (parsed domain\user) |
| `CryptProtectMemory` | `crypt32.dll` | Password buffer before protection |

Each wrapper calls the original — mstsc keeps working normally.

### Credential staging

Target, username, and password often arrive on **separate** hooked calls. The DLL stages them and flushes when all three are present, with exact-match dedup for retries.

### String obfuscation

DLL and API names are stored as rolling-ADD encoded blobs in `obf_enc.h`. `obfDecodeA()` / `obfDecodeW()` decode on the stack; `obfZero()` wipes buffers after use.

---

## Usage

1. Build `tsclient.dll` (see Build below)
2. Convert to shellcode with sRDI if using reflective injection
3. Inject into **mstsc.exe** (not a standalone loader process)
4. Run the pipe server inside your implant before the user connects

### Lab testing

A lab-only pipe server lives in `ReadSecrets_Pipe/` (same project, separate build):

```bat
cd ReadSecrets_Pipe
compile.bat
pipe_listen.exe
rem inject tsclient.dll into mstsc.exe
```

Change pipe name per op in `config.h` (`PIPE_WIN32_PATH` / `PIPE_NT_PATH`).

### Example output

```
==================================================
Captured: 2026-07-08 10:22:41
Target:   192.168.1.50
Username: CORP\jsmith
Password: Passw0rd!

```

---

## Files

| File | Purpose |
|---|---|
| `tsclient.cpp` | Main DLL — hooks, staging, `DllMain` |
| `pipe_client.cpp` / `pipe.h` | Syscall pipe client |
| `syscall.cpp` / `syscall.h` / `syscall.asm` | Hell's Gate resolver + trampoline |
| `nt.h` | NT types/constants |
| `obf.cpp` / `obf.h` / `obf_enc.h` | Rolling-ADD decode + encoded strings |
| `config.h` | Pipe names, frame size limits |
| `detours.h` + `detours/lib.X64/detours.lib` | Microsoft Detours (x64) |
| `compile.bat` | Build `tsclient.dll` |
| `ReadSecrets_Pipe/` | Lab-only pipe server (`pipe_listen.exe`) |

---

## Build

Requires MSVC x64 — run from a **vcvars64** shell:

```bat
vcvars64.bat
cd <project dir>
compile.bat
```

Produces `tsclient.dll` for injection into mstsc.

---

## OPSEC summary

| Concern | Approach |
|---|---|
| Disk artifacts in mstsc | None — pipe client only |
| API telemetry in mstsc | Syscall pipe I/O; hooked APIs resolved via encoded strings |
| Network from mstsc | None — localhost pipe only |
| Duplicate noise | Staging + dedup before send |

---

## Related

- Original technique: [RdpThief by 0x09AL](https://github.com/0x09AL/RdpThief)
- Microsoft Detours: https://github.com/microsoft/Detours
