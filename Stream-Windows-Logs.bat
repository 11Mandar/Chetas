@echo off
setlocal
title Chetas ULPF - Windows Telemetry Shipper
color 0B
cls

echo ================================================================
echo   CHETAS ULPF -- Real-Time Windows Event Log Shipper
echo ================================================================
echo.

set "TARGET_IP=10.180.250.129"
set /p "USER_INPUT=Enter Chetas Server IP (Press Enter for 10.180.250.129): "
if not "%USER_INPUT%"=="" set "TARGET_IP=%USER_INPUT%"

echo.
echo [*] Target Server: http://%TARGET_IP%:3000
echo [*] Starting telemetry stream...
echo.

if exist "%~dp0Stream-Windows-Logs.ps1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Stream-Windows-Logs.ps1" -ChetasServerIp "%TARGET_IP%"
    goto :done
)

if exist "%~dp0scripts\stream_windows_logs.ps1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stream_windows_logs.ps1" -ChetasServerIp "%TARGET_IP%"
    goto :done
)

echo [!] Error: Stream-Windows-Logs.ps1 was not found in: "%~dp0"
echo [*] Please ensure Stream-Windows-Logs.bat and Stream-Windows-Logs.ps1 are in the same folder.
echo.

:done
echo.
echo ================================================================
echo [!] Telemetry streamer stopped.
echo ================================================================
pause
exit /b