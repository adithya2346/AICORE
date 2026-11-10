#!/usr/bin/env python3
"""
AI Data Recovery & Digital Evidence Reconstruction System
Unified Application Launcher (Integrating AEGIS & FalconDataRescue).
"""
import sys
import os
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "ai-data-recovery"
FALCON_DIR = BASE_DIR / "falconDataRescue"

if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
if str(FALCON_DIR / "backend") not in sys.path:
    sys.path.insert(0, str(FALCON_DIR / "backend"))

def print_menu():
    print("=" * 75)
    print("      AI DATA RECOVERY & EVIDENCE RECONSTRUCTION SYSTEM")
    print("=" * 75)
    print(" [0] Launch Desktop App (Real-Time Deleted File & Photo Monitor GUI)")
    print(" [1] AEGIS Forensic CLI Tool (Interactive Recovery)")
    print(" [2] FalconDataRescue: Reconstruct Corrupted File or Folder (PDF/XLSX/Images)")
    print(" [3] FalconDataRescue: Scan NTFS Volume for Deleted Files ($MFT direct)")
    print(" [4] Run Benchmark on Corrupted Test Samples")
    print(" [5] Run Automated Pytest Test Suite")
    print(" [6] Start FastAPI Server & Web Dashboard (http://localhost:8000)")
    print(" [7] Exit")
    print("=" * 75)

def run_falcon_repair():
    print("\n--- FalconDataRescue File & Folder Reconstruction ---")
    sample_dir = FALCON_DIR / "test_corrupted_samples"
    print("Available corrupted test samples:")
    if sample_dir.exists():
        samples = [f.name for f in sample_dir.iterdir() if f.is_file() and not f.name.endswith(".txt")]
        for idx, s in enumerate(samples, 1):
            print(f"  [{idx}] {s}")
    
    target = input("\nEnter file path or sample number: ").strip()
    if target.isdigit() and sample_dir.exists():
        idx = int(target) - 1
        if 0 <= idx < len(samples):
            target_path = str(sample_dir / samples[idx])
        else:
            print("Invalid sample number.")
            return
    else:
        target_path = target

    if not target_path or not os.path.exists(target_path):
        print(f"File not found: {target_path}")
        return

    out_dir = str(BASE_DIR / "recovered_output")
    script = str(FALCON_DIR / "recover_file.py")
    subprocess.run([sys.executable, script, target_path, out_dir])

def run_falcon_ntfs():
    print("\n--- FalconDataRescue Direct NTFS Volume Scanner ---")
    sys.path.insert(0, str(FALCON_DIR / "backend"))
    from app.services import ntfs_deleted_recovery as ndr
    drives = ndr.list_drives()
    print("Available Drives:")
    for d in drives:
        print(f"  [{d['letter']}] {d['path']} ({d['kind']})")
    
    letter = input("Enter drive letter to scan (e.g. C or D): ").strip().upper()[:1]
    if not letter:
        return
    print(f"\nScanning drive {letter}: for deleted records in $MFT (may require Administrator)...")
    try:
        res = ndr.scan_drive_for_deleted(letter, max_items=50)
        items = res.get("items", [])
        print(f"Discovered {len(items)} deleted records on volume {letter}:")
        for it in items[:15]:
            print(f"  - {it['name']} ({it.get('size', 0):,} bytes) [{it.get('type', 'Unknown')}]")
        if len(items) > 15:
            print(f"  ... and {len(items) - 15} more records.")
    except Exception as e:
        print(f"Scan failed: {e}")

def main():
    if len(sys.argv) > 1:
        os.chdir(APP_DIR)
        from recovery_tool import main as tool_main
        tool_main()
        return

    os.chdir(APP_DIR)
    print_menu()
    choice = input("Enter choice [0-7] (default 0): ").strip() or "0"

    if choice == "0":
        from desktop_app import main as app_main
        app_main()
    elif choice == "1":
        from recovery_tool import interactive_menu
        interactive_menu()
    elif choice == "2":
        run_falcon_repair()
    elif choice == "3":
        run_falcon_ntfs()
    elif choice == "4":
        from recovery_tool import cmd_benchmark
        cmd_benchmark(None)
    elif choice == "5":
        subprocess.run([sys.executable, "-m", "pytest", "tests/test_recovery.py", "-v"])
    elif choice == "6":
        print("\nStarting FastAPI server on http://127.0.0.1:8000 ...")
        subprocess.run([sys.executable, "-m", "backend.main"])
    else:
        print("Exiting.")

if __name__ == "__main__":
    main()
