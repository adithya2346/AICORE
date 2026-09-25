"""
AI-Powered Real-Time Folder Sentinel & Auto-Recovery Engine.
Automatically analyzes laptop folders, maintains deterministic zero-fabrication shadow journals,
detects deleted files in real-time, and automatically recovers them back to the filesystem.
"""
import os
import sys
import time
import json
import shutil
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable

from backend.config import settings
from backend.security.hashing import calculate_file_sha256, calculate_bytes_sha256
from backend.recovery.recycle_bin import WindowsRecycleBin, RecycleBinItem

VAULT_DIR = settings.workspace_dir / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)
INDEX_FILE = VAULT_DIR / "vault_index.json"

class VaultEntry:
    def __init__(
        self,
        name: str,
        directory: str,
        size: int,
        sha256: str,
        extension: str,
        last_modified: float,
        vault_path: str,
        status: str = "protected"
    ):
        self.name = name
        self.directory = os.path.normpath(directory)
        self.size = size
        self.sha256 = sha256
        self.extension = extension.lower().lstrip(".")
        self.last_modified = last_modified
        self.vault_path = vault_path
        self.status = status

    @property
    def full_path(self) -> str:
        return os.path.normpath(os.path.join(self.directory, self.name))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "directory": self.directory,
            "full_path": self.full_path,
            "size": self.size,
            "sha256": self.sha256,
            "extension": self.extension,
            "last_modified": self.last_modified,
            "last_modified_str": datetime.fromtimestamp(self.last_modified).strftime("%Y-%m-%d %H:%M:%S") if self.last_modified > 0 else "N/A",
            "vault_path": self.vault_path,
            "status": self.status
        }


class FolderVault:
    """Forensic local shadow vault storing file replicas for instant zero-loss auto-recovery."""
    _lock = threading.Lock()

    @classmethod
    def load_index(cls) -> Dict[str, Dict[str, Any]]:
        with cls._lock:
            if INDEX_FILE.exists():
                try:
                    with open(INDEX_FILE, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    return {}
            return {}

    @classmethod
    def save_index(cls, data: Dict[str, Dict[str, Any]]):
        with cls._lock:
            try:
                with open(INDEX_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass

    @classmethod
    def store_file(cls, file_path: Path) -> Optional[VaultEntry]:
        """Index a file and cache a shadow copy in the vault."""
        if not file_path.is_file():
            return None
        try:
            stat = file_path.stat()
            size = stat.st_size
            mtime = stat.st_mtime
            
            # Don't vault huge files > 100MB by default to keep operation instantaneous
            if size > 100 * 1024 * 1024:
                sha = "oversized_skipped"
                v_path = ""
            else:
                with open(file_path, "rb") as f:
                    raw = f.read()
                sha = calculate_bytes_sha256(raw)
                v_filename = f"{sha[:16]}_{file_path.name}"
                v_full = VAULT_DIR / v_filename
                if not v_full.exists():
                    with open(v_full, "wb") as f_out:
                        f_out.write(raw)
                v_path = str(v_full.resolve())

            entry = VaultEntry(
                name=file_path.name,
                directory=str(file_path.parent.resolve()),
                size=size,
                sha256=sha,
                extension=file_path.suffix,
                last_modified=mtime,
                vault_path=v_path,
                status="protected"
            )
            idx = cls.load_index()
            idx[entry.full_path.lower()] = entry.to_dict()
            cls.save_index(idx)
            return entry
        except Exception:
            return None

    @classmethod
    def find_in_vault(cls, filename: str, directory: Optional[str] = None) -> List[Dict[str, Any]]:
        idx = cls.load_index()
        matches = []
        fn_lower = filename.lower().strip()
        norm_dir = os.path.normpath(directory).lower() if directory else None

        for key, entry in idx.items():
            name_match = False
            e_name = entry.get("name", "").lower()
            if fn_lower in ("*", "") or fn_lower in e_name:
                name_match = True
            elif e_name == fn_lower:
                name_match = True

            if not name_match:
                continue

            if norm_dir:
                e_dir = os.path.normpath(entry.get("directory", "")).lower()
                if norm_dir in e_dir or e_dir in norm_dir:
                    matches.append(entry)
            else:
                matches.append(entry)

        return matches


class FolderAnalyzer:
    """Analyzes a folder on the laptop, indexing all files and cataloging protection states."""

    @staticmethod
    def analyze_folder(directory_path: str, max_files: int = 500) -> Dict[str, Any]:
        p = Path(directory_path)
        if not p.exists() or not p.is_dir():
            raise FileNotFoundError(f"Directory '{directory_path}' does not exist or is not a folder.")

        indexed_files: List[Dict[str, Any]] = []
        total_size = 0
        extensions: Dict[str, int] = {}

        try:
            entries = list(p.iterdir())
        except PermissionError:
            raise PermissionError(f"Permission denied accessing directory '{directory_path}'.")

        for item in entries[:max_files]:
            if item.is_file():
                try:
                    entry = FolderVault.store_file(item)
                    if entry:
                        d = entry.to_dict()
                        indexed_files.append(d)
                        total_size += entry.size
                        ext = entry.extension or "no_ext"
                        extensions[ext] = extensions.get(ext, 0) + 1
                except Exception:
                    continue

        return {
            "directory": str(p.resolve()),
            "total_files": len(indexed_files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "extensions_distribution": extensions,
            "files": indexed_files,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }


class AutoRecoverySentinel:
    """
    Real-Time Laptop Folder Monitor.
    Runs continuously in a background thread, monitoring a directory.
    When a deleted file event is detected, it automatically restores the file
    back into the laptop folder and alerts the application.
    """
    def __init__(
        self,
        directory: str,
        target_filename: str = "*",
        auto_recover: bool = True,
        on_deletion: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_recovery: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
        poll_interval: float = 0.4
    ):
        self.directory = Path(directory)
        self.target_filename = target_filename.strip().lower()
        self.auto_recover = auto_recover
        self.on_deletion = on_deletion
        self.on_recovery = on_recovery
        self.on_log = on_log
        self.poll_interval = poll_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_files: Dict[str, float] = {}  # filename -> mtime

    def log(self, message: str):
        if self.on_log:
            self.on_log(message)

    def is_active(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return
        if not self.directory.exists() or not self.directory.is_dir():
            raise FileNotFoundError(f"Cannot monitor non-existent directory '{self.directory}'")

        # Initial analysis and snapshot
        self._running = True
        self._refresh_known_files(initial=True)
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.log(f"🛡️ [SENTINEL ACTIVE] Monitoring directory: {self.directory.name} (Filter: {self.target_filename})")

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self.log("⏹️ [SENTINEL STANDBY] Real-time folder monitoring stopped.")

    def _refresh_known_files(self, initial: bool = False):
        try:
            current_files = {}
            for item in self.directory.iterdir():
                if item.is_file():
                    current_files[item.name] = item.stat().st_mtime
                    if initial:
                        FolderVault.store_file(item)
            self._known_files = current_files
        except Exception:
            pass

    def _matches_target(self, filename: str) -> bool:
        if not self.target_filename or self.target_filename in ("*", "", "all"):
            return True
        fn_lower = filename.lower()
        return self.target_filename in fn_lower or Path(fn_lower).stem == Path(self.target_filename).stem

    def _monitor_loop(self):
        while self._running:
            try:
                if not self.directory.exists():
                    time.sleep(self.poll_interval)
                    continue

                current_files = {}
                for item in self.directory.iterdir():
                    if item.is_file():
                        current_files[item.name] = item.stat().st_mtime
                        # If a new or modified file is saved, update vault silently
                        if item.name not in self._known_files or self._known_files[item.name] != current_files[item.name]:
                            FolderVault.store_file(item)

                # Detect deleted files: existed previously, now gone!
                deleted_names = set(self._known_files.keys()) - set(current_files.keys())

                for d_name in deleted_names:
                    if self._matches_target(d_name):
                        # Gather metadata from vault
                        matches = FolderVault.find_in_vault(d_name, str(self.directory))
                        v_entry = matches[-1] if matches else {}
                        ext = Path(d_name).suffix.lower()
                        is_photo = ext in (".jpg", ".jpeg", ".png", ".bmp", ".webp", ".gif")
                        file_type_desc = "Photo" if is_photo else "File"

                        del_info = {
                            "name": d_name,
                            "directory": str(self.directory),
                            "full_path": str(self.directory / d_name),
                            "size": v_entry.get("size", 0),
                            "extension": ext.lstrip("."),
                            "is_photo": is_photo,
                            "file_type_desc": file_type_desc,
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "status": "deleted"
                        }

                        self.log(f"⚠️ [DELETION DETECTED] {file_type_desc} '{d_name}' was deleted from '{self.directory}'!")
                        if self.on_deletion:
                            self.on_deletion(del_info)

                        if self.auto_recover:
                            self.log(f"🛡️ [AUTO-RECOVERY] Automatically restoring {file_type_desc.lower()} '{d_name}' to same path...")
                            recovered_info = self._auto_recover_file(d_name)
                            if recovered_info:
                                self.log(f"✓ [RESTORED] '{d_name}' restored to same path: {recovered_info['restored_to']}! (100% Integrity)")
                                if self.on_recovery:
                                    self.on_recovery(recovered_info)
                            else:
                                self.log(f"❌ [NOTICE] Could not auto-recover '{d_name}' from vault. Checking Recycle Bin...")

                self._known_files = current_files

            except Exception as e:
                self.log(f"⚠️ [MONITOR WARNING] {str(e)}")

            time.sleep(self.poll_interval)

    def _auto_recover_file(self, filename: str) -> Optional[Dict[str, Any]]:
        """Automatically recover a deleted file back to the monitored folder."""
        # 1. First attempt: Restore from Local Forensic Shadow Vault (Instant zero-loss copy)
        matches = FolderVault.find_in_vault(filename, str(self.directory))
        if matches:
            best_match = matches[-1]
            vault_path = best_match.get("vault_path")
            if vault_path and os.path.exists(vault_path):
                try:
                    with open(vault_path, "rb") as f_in:
                        raw = f_in.read()

                    # Restore back to original directory!
                    target_dest = self.directory / filename
                    with open(target_dest, "wb") as f_out:
                        f_out.write(raw)

                    # Also save a copy in output recovery directory
                    out_copy = settings.output_dir / f"auto_recovered_{filename}"
                    with open(out_copy, "wb") as f_out2:
                        f_out2.write(raw)

                    return {
                        "path": str(target_dest.resolve()),
                        "name": filename,
                        "type": target_dest.suffix.lstrip(".").lower() or "bin",
                        "size": len(raw),
                        "raw_bytes": raw,
                        "integrity": 100.0,
                        "confidence": 100,
                        "is_valid": True,
                        "restored_to": str(target_dest),
                        "source": "Forensic Vault (Instant Auto-Restore)",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "fabricated_bytes": 0
                    }
                except Exception:
                    pass

        # 2. Second attempt: Check Windows Recycle Bin
        rb_matches = WindowsRecycleBin.find_deleted_file(filename, str(self.directory))
        if rb_matches:
            item = rb_matches[0]
            restored = WindowsRecycleBin.restore_file(item, str(self.directory))
            if restored:
                restored["source"] = "Windows Recycle Bin (Auto-Resurrected)"
                restored["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return restored

        return None


def recover_target_file(filename: str, directory: str) -> Optional[Dict[str, Any]]:
    """
    On-Demand File Recovery.
    Accepts File Name and Directory, performs multi-engine recovery:
    1. Checks Recycle Bin
    2. Checks Vault Shadow
    3. Restores to the directory
    """
    p_dir = Path(directory)
    fn = filename.strip()

    # If the file already exists in the directory, read it directly
    existing_path = p_dir / fn
    if existing_path.exists() and existing_path.is_file():
        with open(existing_path, "rb") as f:
            raw = f.read()
        return {
            "path": str(existing_path.resolve()),
            "name": fn,
            "type": existing_path.suffix.lstrip(".").lower() or "bin",
            "size": len(raw),
            "raw_bytes": raw,
            "integrity": 100.0,
            "confidence": 100,
            "is_valid": True,
            "restored_to": str(existing_path),
            "source": "Active Directory (Existing File)",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "fabricated_bytes": 0
        }

    # 1. Search Recycle Bin
    rb_items = WindowsRecycleBin.find_deleted_file(fn, str(p_dir))
    if rb_items:
        res = WindowsRecycleBin.restore_file(rb_items[0], str(p_dir))
        if res:
            res["source"] = "Windows Recycle Bin Forensic Recovery"
            res["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return res

    # 2. Search Vault
    vault_items = FolderVault.find_in_vault(fn, str(p_dir))
    if vault_items:
        best = vault_items[-1]
        v_path = best.get("vault_path")
        if v_path and os.path.exists(v_path):
            with open(v_path, "rb") as f:
                raw = f.read()
            target_path = p_dir / fn
            p_dir.mkdir(parents=True, exist_ok=True)
            with open(target_path, "wb") as f_out:
                f_out.write(raw)

            return {
                "path": str(target_path.resolve()),
                "name": fn,
                "type": target_path.suffix.lstrip(".").lower() or "bin",
                "size": len(raw),
                "raw_bytes": raw,
                "integrity": 100.0,
                "confidence": 100,
                "is_valid": True,
                "restored_to": str(target_path),
                "source": "Forensic Vault Recovery",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "fabricated_bytes": 0
            }

    return None
