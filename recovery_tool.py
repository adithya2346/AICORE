#!/usr/bin/env python3
"""
Root entrypoint for AI-Assisted Data Recovery CLI Tool.
Delegates directly to ai-data-recovery/recovery_tool.py.
"""
import sys
from pathlib import Path

# Add ai-data-recovery to python path
pkg_dir = Path(__file__).resolve().parent / "ai-data-recovery"
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))

# Change working directory so relative dataset and model paths resolve correctly
import os
os.chdir(pkg_dir)

from recovery_tool import main

if __name__ == "__main__":
    main()
