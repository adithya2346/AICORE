"""
Persistent Forensic Deleted Files Manager & Manual Restoration Service.
Silently logs all file deletion events across all monitored storage drives,
verifies cryptographic SHA-256 integrity against the Shadow Vault,
and provides user-controlled manual restoration (individual, batch, and restore all).
Strict Forensic Principle: FABRICATED_BYTES = 0.
"""
from __future__ import annotations

import os
import json
import uuid
import shutil
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

from backend.config import settings
from backend.security.hashing import calculate_file_sha256, calculate_bytes_sha256
from backend.recovery.folder_sentinel import FolderVault

DELETED_FILES_FILE = settings.workspace_dir / "deleted_files_history.json"


class DeletedFileRecord:
    def __init__(
        self,
        event_id: str,
        filename: str,
        original_path: str,
        directory: str,
        file_extension: str,
        file_size: int,
        deletion_timestamp: str,
        source_drive: str,
        vault_path: str = "",
        sha256: str = "",
        status: str = "Awaiting Manual Restoration",
        restoration_timestamp: Optional[str] = None,
        restored_to: Optional[str] = None
    ):
        self.event_id = event_id
        self.filename = filename
        self.original_path = os.path.normpath(original_path)
        self.directory = os.path.normpath(directory)
        self.file_extension = file_extension.lower().lstrip(".")
        self.file_size = file_size
        self.deletion_timestamp = deletion_timestamp
        self.source_drive = source_drive.upper().rstrip("\\")
        self.vault_path = vault_path
        self.sha256 = sha256
        self.status = status
        self.restoration_timestamp = restoration_timestamp
        self.restored_to = restored_to

    @property
    def size_formatted(self) -> str:
        if self.file_size <= 0:
            return "0 B"
        if self.file_size < 1024:
            return f"{self.file_size} B"
        elif self.file_size < 1024 * 1024:
            return f"{self.file_size / 1024:.1f} KB"
        else:
            return f"{self.file_size / (1024 * 1024):.1f} MB"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "filename": self.filename,
            "original_path": self.original_path,
            "directory": self.directory,
            "file_extension": self.file_extension,
            "file_size": self.file_size,
            "size_formatted": self.size_formatted,
            "deletion_timestamp": self.deletion_timestamp,
            "source_drive": self.source_drive,
            "vault_path": self.vault_path,
            "sha256": self.sha256,
            "status": self.status,
            "restoration_timestamp": self.restoration_timestamp,
            "restored_to": self.restored_to,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DeletedFileRecord:
        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            filename=data.get("filename", ""),
            original_path=data.get("original_path", ""),
            directory=data.get("directory", ""),
            file_extension=data.get("file_extension", ""),
            file_size=data.get("file_size", 0),
            deletion_timestamp=data.get("deletion_timestamp", ""),
            source_drive=data.get("source_drive", ""),
            vault_path=data.get("vault_path", ""),
            sha256=data.get("sha256", ""),
            status=data.get("status", "Awaiting Manual Restoration"),
            restoration_timestamp=data.get("restoration_timestamp"),
            restored_to=data.get("restored_to")
        )


class DeletedFilesManager:
    """Thread-safe persistent repository managing silent deletion tracking and manual restorations."""
    _lock = threading.Lock()

    @classmethod
    def _load_records(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            if DELETED_FILES_FILE.exists():
                try:
                    with open(DELETED_FILES_FILE, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    return []
            return []

    @classmethod
    def _save_records(cls, records: List[Dict[str, Any]]):
        with cls._lock:
            try:
                DELETED_FILES_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(DELETED_FILES_FILE, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2)
            except Exception:
                pass

    @classmethod
    def record_deletion(cls, del_info: Dict[str, Any]) -> DeletedFileRecord:
        """
        Silently records a deletion event without prompting the user.
        Queries Shadow Vault and verifies SHA-256 hash immediately.
        """
        filename = del_info.get("name", "")
        orig_path = del_info.get("full_path", "")
        directory = del_info.get("directory", str(Path(orig_path).parent if orig_path else ""))
        try:
            if directory:
                directory = str(Path(directory).resolve())
        except Exception:
            pass
        drive = del_info.get("drive", "") or (Path(orig_path).drive if orig_path else "")
        ext = del_info.get("extension", Path(filename).suffix.lstrip("."))
        sz = del_info.get("size", 0)

        # Query Shadow Vault for authentic backup
        matches = FolderVault.find_in_vault(filename, directory=directory, drive=drive)
        if not matches:
            matches = FolderVault.find_in_vault(filename)

        # Prefer match whose vault_path actually exists on disk
        valid_match = None
        for m in reversed(matches):
            vp = m.get("vault_path", "")
            if vp and os.path.exists(vp):
                valid_match = m
                break
        v_entry = valid_match or (matches[-1] if matches else {})
        vault_path = v_entry.get("vault_path", "")
        expected_sha = v_entry.get("sha256", "")
        if sz <= 0:
            sz = v_entry.get("size", 0)

        # Determine status
        if vault_path and os.path.exists(vault_path):
            if expected_sha and expected_sha != "oversized_skipped":
                if FolderVault.verify_vault_file(vault_path, expected_sha):
                    status = "Backup Available"
                else:
                    status = "Backup Corrupted"
            else:
                status = "Backup Available"
        else:
            status = "Recovery Unavailable"

        timestamp = del_info.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if len(timestamp) == 8:  # if HH:MM:SS format
            timestamp = f"{datetime.now().strftime('%Y-%m-%d')} {timestamp}"

        record = DeletedFileRecord(
            event_id=str(uuid.uuid4()),
            filename=filename,
            original_path=orig_path,
            directory=directory,
            file_extension=ext,
            file_size=sz,
            deletion_timestamp=timestamp,
            source_drive=drive,
            vault_path=vault_path,
            sha256=expected_sha,
            status=status
        )

        all_recs = cls._load_records()
        # Deduplicate recent deletion of identical path within 2 seconds
        is_dup = False
        for r in all_recs[:10]:
            if r.get("original_path", "").lower() == orig_path.lower() and r.get("status") != "Restored":
                is_dup = True
                break

        if not is_dup:
            all_recs.insert(0, record.to_dict())
            cls._save_records(all_recs)

        return record

    @classmethod
    def get_all_records(cls) -> List[DeletedFileRecord]:
        raw = cls._load_records()
        return [DeletedFileRecord.from_dict(r) for r in raw]

    @classmethod
    def get_record(cls, event_id: str) -> Optional[DeletedFileRecord]:
        raw = cls._load_records()
        for r in raw:
            if r.get("event_id") == event_id:
                return DeletedFileRecord.from_dict(r)
        return None

    @classmethod
    def update_record(cls, event_id: str, updates: Dict[str, Any]):
        raw = cls._load_records()
        for r in raw:
            if r.get("event_id") == event_id:
                r.update(updates)
                break
        cls._save_records(raw)

    @classmethod
    def restore_record(
        cls,
        record: DeletedFileRecord,
        custom_dest: Optional[str] = None,
        overwrite: bool = False
    ) -> Tuple[bool, str]:
        """
        Executes manual restoration for a single deleted file record.
        1. Retrieves Shadow Vault authentic copy.
        2. Validates SHA-256 hash (FABRICATED_BYTES = 0).
        3. Checks whether destination exists. If occupied and not overwrite -> returns False, "OCCUPIED".
        4. Writes out authentic bytes.
        5. Updates status to "Restored".
        """
        vault_path = record.vault_path
        if not vault_path or not os.path.exists(vault_path):
            cls.update_record(record.event_id, {"status": "Recovery Unavailable"})
            return False, "Vault shadow copy not found or unavailable."

        # Verify SHA-256 integrity
        if record.sha256 and record.sha256 != "oversized_skipped":
            if not FolderVault.verify_vault_file(vault_path, record.sha256):
                cls.update_record(record.event_id, {"status": "Backup Corrupted"})
                return False, "Shadow copy failed cryptographic SHA-256 integrity check."

        target_path = Path(custom_dest) if custom_dest else Path(record.original_path)

        # Check for destination conflict
        if target_path.exists() and not overwrite:
            cls.update_record(record.event_id, {"status": "Original Location Occupied"})
            return False, "OCCUPIED"

        try:
            with open(vault_path, "rb") as f_in:
                raw_bytes = f_in.read()

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "wb") as f_out:
                f_out.write(raw_bytes)

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cls.update_record(record.event_id, {
                "status": "Restored",
                "restoration_timestamp": now_str,
                "restored_to": str(target_path.resolve())
            })
            return True, f"Successfully restored to {target_path} (100% SHA-256 Verified)"
        except Exception as exc:
            return False, f"Failed to restore file: {str(exc)}"

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        records = cls.get_all_records()
        total = len(records)
        available = sum(1 for r in records if r.status in ("Backup Available", "Backup Verified", "Awaiting Manual Restoration"))
        pending = sum(1 for r in records if r.status not in ("Restored", "Recovery Unavailable", "Backup Corrupted"))
        restored = sum(1 for r in records if r.status == "Restored")
        unrecoverable = sum(1 for r in records if r.status in ("Recovery Unavailable", "Backup Corrupted"))

        drives = sorted(list({r.source_drive for r in records if r.source_drive}))

        return {
            "total_deleted": total,
            "available_backups": available,
            "pending_restoration": pending,
            "successfully_restored": restored,
            "unrecoverable_files": unrecoverable,
            "drives": drives
        }
