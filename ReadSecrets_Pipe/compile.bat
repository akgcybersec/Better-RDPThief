@ECHO OFF

echo [*] Building pipe_listen.exe (lab only)...
cl.exe /nologo /Ox /W0 /GS- /DNDEBUG /I.. pipe_listen.cpp pipe_server.cpp /MT /link /OUT:pipe_listen.exe
if errorlevel 1 exit /b 1

del *.obj *.lib *.exp >nul 2>&1
echo [+] Build complete: pipe_listen.exe
