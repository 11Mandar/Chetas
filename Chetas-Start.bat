@echo off
title Chetas ULPF SOC Command Center
cd /d "%~dp0"

echo [Chetas] Starting Universal Log Pre-processing Framework...
echo [Chetas] Automated collectors: Windows Event Logs, UDP Syslog (1514), File Watcher (incoming_logs/)
echo.

:: Start Node server in background
start "" /b node server/index.js

:: Wait 2 seconds for server to bind port
timeout /t 2 /nobreak >nul

:: Automatically open default browser without needing terminal interaction
start http://localhost:3000

echo [Chetas] Command Center launched in default web browser.
