@echo off
title AEGIS - AI Forensic Data Recovery Desktop App
cd /d "%~dp0ai-data-recovery"
set PYTHONPATH=%~dp0falconDataRescue\backend;%~dp0ai-data-recovery;%PYTHONPATH%
python desktop_app.py
pause
