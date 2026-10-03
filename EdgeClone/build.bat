@echo off
setlocal
set PROJ=%~dp0EdgeClone.csproj
set BIN=%~dp0bin\Release\net48\EdgeBackup.exe
set OUT=%~dp0EdgeBackup.exe

echo Building EdgeBackup...
dotnet build "%PROJ%" -c Release
if %errorlevel% equ 0 (
    copy /Y "%BIN%" "%OUT%" >nul
    echo [OK] Built: %OUT%
) else (
    echo [FAIL] Build failed.
    exit /b 1
)
