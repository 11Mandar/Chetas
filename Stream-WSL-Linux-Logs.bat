@echo off
title Chetas ULPF - WSL Linux Telemetry Shipper
color 0A
cls

echo ================================================================
echo   CHETAS ULPF -- Real-Time WSL Ubuntu Linux Log Shipper
echo ================================================================
echo.
echo [*] Launching Ubuntu Linux WSL and streaming real Linux telemetry...
echo [*] Press Ctrl+C anytime to stop streaming.
echo.

wsl /mnt/d/ULPF/Chetas/scripts/stream_wsl_logs.sh

echo.
echo [!] Shipper stopped.
pause
