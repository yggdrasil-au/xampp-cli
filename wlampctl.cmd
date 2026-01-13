@echo off
setlocal

set "EXE=%~dp0source\xampp-build\Built\installed-xampp\wlampctl.exe"

if not exist "%EXE%" (
    echo [wlampctl] ERROR: not found: "%EXE%"
    exit /b 1
)

"%EXE%" %*
