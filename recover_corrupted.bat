@echo off
title FalconDataRescue - Corrupted File Recovery
cd /d "%~dp0"
if "%~1"=="" (
    echo [FalconDataRescue] Drag and drop a corrupted file onto this .bat or enter file path:
    set /p TARGET_FILE="Enter file path: "
) else (
    set TARGET_FILE=%~1
)

python falconDataRescue\recover_file.py "%TARGET_FILE%" recovered_output
pause

