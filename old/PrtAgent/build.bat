@echo off
setlocal
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
set OUT=%~dp0PrtAgent.exe
set SRC=%~dp0Program.cs

echo Building PrtAgent...
"%CSC%" /out:"%OUT%" /target:exe /platform:x64 /r:System.dll "%SRC%"
if %errorlevel% equ 0 (
    echo [OK] Built: %OUT%
) else (
    echo [FAIL] Build failed.
    exit /b 1
)
