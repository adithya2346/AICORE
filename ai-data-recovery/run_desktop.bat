@echo off
title AEGIS - AI Forensic Data Recovery Desktop App
cd /d "%~dp0"
set PYTHONPATH=%~dp0..\falconDataRescue\backend;%~dp0;%PYTHONPATH%
python desktop_app.py
pause

