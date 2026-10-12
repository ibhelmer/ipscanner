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
".venv\Scripts\python.exe" ipscanner.py %*
if errorlevel 1 (
    echo.
    echo Programmet blev afsluttet med en fejl. Se meddelelsen ovenfor.
    pause
    exit /b 1
)
exit /b 0
