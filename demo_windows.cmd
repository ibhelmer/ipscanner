@echo off
rem Copyright 2026 Ib Helmer Nielsen
rem SPDX-License-Identifier: Apache-2.0
setlocal EnableExtensions
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto use_venv
where py >nul 2>&1
if errorlevel 1 goto use_python
py -3 ipscanner.py --demo
goto finished
:use_python
python ipscanner.py --demo
goto finished
:use_venv
".venv\Scripts\python.exe" ipscanner.py --demo
:finished
if errorlevel 1 (
    echo.
    echo Demo kraever Python 3.10 eller nyere med Tcl/Tk.
    pause
    exit /b 1
)
exit /b 0
