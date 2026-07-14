@ECHO OFF

if exist tsclient.dll (
    del /F tsclient.dll >nul 2>&1
    if exist tsclient.dll (
        echo [!] tsclient.dll is locked. Close any process using it, then retry.
        exit /b 1
    )
)

echo [*] Assembling syscall stub...
ml64 /nologo /c /Fo syscall_asm.obj syscall.asm
if errorlevel 1 exit /b 1

echo [*] Building tsclient.dll...
cl.exe /nologo /Ox /W0 /GS- /DNDEBUG tsclient.cpp obf.cpp pipe_client.cpp syscall.cpp syscall_asm.obj /MT /link /DLL detours\lib.X64\detours.lib /OUT:tsclient.dll
if errorlevel 1 exit /b 1

del *.obj *.lib *.exp >nul 2>&1
echo [+] Build complete: tsclient.dll
