@echo off
title Stop Chetas ULPF
cd /d "%~dp0"

echo [Chetas] Stopping background services on port 3000 and 1514...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000 "') do (
  taskkill /F /PID %%a >nul 2>&1
)

echo [Chetas] Server stopped.
pause
