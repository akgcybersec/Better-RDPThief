# ReadSecrets_Pipe (lab only)

Reference named-pipe **server** for local testing of `tsclient.dll`. Part of the Detours project — not a separate hooking technique. Do not deploy on engagement; embed the server loop in your implant instead.

## Build

From a **vcvars64** shell:

```bat
cd 05.Hooking\01.Detours\ReadSecrets_Pipe
compile.bat
```

Uses `../config.h` so the pipe name stays in sync with the DLL client.

## Test

```bat
pipe_listen.exe
rem inject tsclient.dll into mstsc.exe
rem RDP connect with saved credentials → output prints here
```
