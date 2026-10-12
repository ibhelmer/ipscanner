@echo off
rem Copyright 2026 Ib Helmer Nielsen
rem SPDX-License-Identifier: Apache-2.0
setlocal EnableExtensions
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Det virtuelle miljoe mangler. Koer install_windows.cmd foerst.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" ipscanner.py --diagnostics netkort_diagnostik.txt
if errorlevel 1 (
    echo Rapporten kunne ikke oprettes. Se fejl ovenfor.
    pause
    exit /b 1
)
echo.
echo Rapporten indeholder lokale IP-adresser, MAC-adresser og netkortnavne.
echo Kontroller indholdet foer deling.
notepad.exe netkort_diagnostik.txt
exit /b 0
