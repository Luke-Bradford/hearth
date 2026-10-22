@echo off
rem Starts Hearth. Double-click, or point Task Scheduler at this file.
title Hearth
cd /d "%~dp0"
python hearth.py
if errorlevel 1 pause
