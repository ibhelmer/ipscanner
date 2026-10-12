@echo off
rem Copyright 2026 Ib Helmer Nielsen
rem SPDX-License-Identifier: Apache-2.0
setlocal EnableExtensions
cd /d "%~dp0"
echo IP Scanner - installation i et lokalt virtuelt miljoe
if exist ".venv\Scripts\python.exe" goto install
where py >nul 2>&1
if errorlevel 1 goto fallback_python
py -3 -m venv .venv
if errorlevel 1 goto failed
goto install
:fallback_python
where python >nul 2>&1
if errorlevel 1 goto missing_python
python -m venv .venv
if errorlevel 1 goto failed
:install
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo.
echo Python-afhaengigheden er installeret.
echo Npcap skal installeres separat fra https://npcap.com/
echo Start derefter start_windows.cmd - normalt som administrator.
echo Demo kan startes med demo_windows.cmd uden Npcap.
pause
exit /b 0
:missing_python
echo Python blev ikke fundet. Installer Python 3.10 eller nyere med Tcl/Tk.
goto failed
:failed
echo.
echo Installationen mislykkedes. Se fejlmeddelelsen ovenfor og README.md.
pause
exit /b 1
