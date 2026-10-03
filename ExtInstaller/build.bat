@echo off
setlocal
set PROJ=%~dp0ExtInstaller.csproj
set BIN=%~dp0bin\Release\net48\ExtInstaller.exe
set OUT=%~dp0ExtInstaller.exe

echo Building ExtInstaller...
dotnet build "%PROJ%" -c Release
if %errorlevel% equ 0 (
    copy /Y "%BIN%" "%OUT%" >nul
    echo [OK] Built: %OUT%
) else (
    echo [FAIL] Build failed.
    exit /b 1
)
