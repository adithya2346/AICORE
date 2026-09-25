#!/usr/bin/env python3
"""
AI Data Recovery & Digital Evidence Reconstruction System
Unified Application Launcher.
"""
import sys
import os
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "ai-data-recovery"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

os.chdir(APP_DIR)

def print_menu():
    print("=" * 70)
    print(" AI DATA RECOVERY & EVIDENCE RECONSTRUCTION SYSTEM")
    print("=" * 70)
    print(" [0] Launch Desktop App (Real-Time Deleted File & Photo Monitor GUI)")
    print(" [1] Run Python Forensic CLI Tool (Interactive Recovery)")
    print(" [2] Run Forensic Reconstruction Benchmark")
    print(" [3] Run Automated Pytest Test Suite (17 Tests)")
    print(" [4] Start FastAPI Server & Web Dashboard (http://localhost:8000)")
    print(" [5] Exit")
    print("=" * 70)

def main():
    if len(sys.argv) > 1:
        # Pass-through arguments to recovery_tool
        from recovery_tool import main as tool_main
        tool_main()
        return

    print_menu()
    choice = input("Enter choice [0-5] (default 0): ").strip() or "0"

    if choice == "0":
        from desktop_app import main as app_main
        app_main()
    elif choice == "1":
        from recovery_tool import interactive_menu
        interactive_menu()
    elif choice == "2":
        from recovery_tool import cmd_benchmark
        cmd_benchmark(None)
    elif choice == "3":
        subprocess.run([sys.executable, "-m", "pytest", "tests/test_recovery.py", "-v"])
    elif choice == "4":
        print("\nStarting FastAPI server on http://127.0.0.1:8000 ...")
        subprocess.run([sys.executable, "-m", "backend.main"])
    else:
        print("Exiting.")

if __name__ == "__main__":
    main()
