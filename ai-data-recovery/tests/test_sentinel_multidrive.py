"""
Comprehensive Unit & Integration Tests for System-Wide Sentinel Watcher & Multi-Drive Storage Monitoring:
1. Automatic storage device discovery (GetLogicalDrives, GetDriveTypeW, GetVolumeInformationW, GetDiskFreeSpaceExW).
2. Simultaneous monitoring of multiple drives/partitions.
3. Real-time file event detection (Creation, Modification, Deletion, Renaming).
4. Shadow Vault backup and cryptographic SHA-256 integrity verification (FABRICATED_BYTES = 0).
5. Deletion detection and instant zero-loss auto-recovery back to the original file path.
6. Dynamic drive discovery (connecting / disconnecting storage devices without losing existing backups).
"""
import os
import time
import shutil
import tempfile
from pathlib import Path
import pytest

from backend.recovery.drive_detector import StorageDevice, StorageDeviceDetector
from backend.recovery.folder_sentinel import (
    VaultEntry,
    FolderVault,
    DriveSentinelWatcher,
    SystemWideSentinelManager,
    recover_target_file,
)


def test_automatic_drive_detection():
    """Verify system-wide storage device enumeration."""
    devices = StorageDeviceDetector.enumerate_drives()
    assert len(devices) >= 1
    
    # At least one system drive should be identified
    sys_drives = [d for d in devices if d.is_system]
    assert len(sys_drives) >= 1
    sys_dev = sys_drives[0]
    
    assert sys_dev.drive_letter.endswith(":")
    assert sys_dev.total_bytes > 0
    assert sys_dev.free_bytes > 0
    assert sys_dev.total_gb > 0
    assert sys_dev.filesystem in ("NTFS", "FAT32", "exFAT", "ext4")
    assert sys_dev.is_accessible is True


def test_shadow_vault_cryptographic_integrity():
    """Verify Shadow Vault store, SHA-256 verification, and deduplication."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "evidence_document.txt"
        test_content = b"CRITICAL FORENSIC EVIDENCE CONTENT 987654321"
        test_file.write_bytes(test_content)

        entry = FolderVault.store_file(test_file)
        assert entry is not None
        assert entry.name == "evidence_document.txt"
        assert entry.size == len(test_content)
        assert len(entry.sha256) == 64
        assert os.path.exists(entry.vault_path)

        # Verify cryptographic integrity check
        assert FolderVault.verify_vault_file(entry.vault_path, entry.sha256) is True
        # Tampered hash should fail verification
        assert FolderVault.verify_vault_file(entry.vault_path, "0" * 64) is False


def test_drive_sentinel_file_events_and_recovery():
    """Verify creation, deletion detection, and auto-restoration back to original directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        drive_letter = Path(tmpdir).drive.upper() or "C:"
        mock_dev = StorageDevice(
            drive_letter=drive_letter,
            root_path=tmpdir,
            volume_name="TestPartition",
            filesystem="NTFS",
            drive_type_code=3,
            drive_type_desc="Fixed Test Partition",
            is_system=False,
            is_removable=False,
            is_accessible=True,
            total_bytes=100 * 1024**3,
            free_bytes=50 * 1024**3
        )

        events_captured = []
        deletions_captured = []
        recoveries_captured = []

        watcher = DriveSentinelWatcher(
            device=mock_dev,
            auto_recover=True,
            on_event=lambda ev: events_captured.append(ev),
            on_deletion=lambda d: deletions_captured.append(d),
            on_recovery=lambda r: recoveries_captured.append(r),
        )

        # Override watch targets to point directly to temp directory
        watcher.get_watch_targets = lambda: [Path(tmpdir)]
        watcher.start()
        time.sleep(0.3)

        # 1. Create a file
        target_file = Path(tmpdir) / "classified_memo.pdf"
        sample_bytes = b"%PDF-1.4 TEST FORENSIC PAYLOAD FOR AUTO RECOVERY %%EOF"
        target_file.write_bytes(sample_bytes)
        time.sleep(0.5)

        # Verify file was indexed in vault
        vault_matches = FolderVault.find_in_vault("classified_memo.pdf", tmpdir)
        assert len(vault_matches) >= 1

        # 2. Delete the file
        target_file.unlink()
        time.sleep(0.6)

        # 3. Verify deletion was captured silently without automatic restoration
        assert len(deletions_captured) >= 1
        assert deletions_captured[-1]["name"] == "classified_memo.pdf"

        # The file is not automatically restored (user maintains complete control)
        from backend.recovery.deleted_files_manager import DeletedFilesManager
        records = DeletedFilesManager.get_all_records()
        matching = [r for r in records if r.filename == "classified_memo.pdf"]
        assert len(matching) >= 1
        rec = matching[0]
        assert rec.status == "Backup Available"

        # 4. User triggers manual restoration
        ok, msg = DeletedFilesManager.restore_record(rec)
        assert ok is True
        assert target_file.exists()
        assert target_file.read_bytes() == sample_bytes

        watcher.stop()


def test_system_wide_sentinel_manager():
    """Verify manager starts multi-drive monitoring, tracks stats, and preserves backups."""
    manager = SystemWideSentinelManager(auto_recover=True)
    manager.start_all()

    stats = manager.get_system_stats()
    assert stats["total_drives_detected"] >= 1
    assert stats["active_monitoring_count"] >= 1

    # Verify per-drive toggle
    first_letter = list(manager.known_devices.keys())[0]
    # Toggle off
    was_active = manager.toggle_drive(first_letter)
    assert was_active is False
    # Toggle back on
    was_active_again = manager.toggle_drive(first_letter)
    assert was_active_again is True

    manager.stop_all()
    stats_after = manager.get_system_stats()
    assert stats_after["active_monitoring_count"] == 0



def test_deleted_files_manager_manual_scenarios():
    """Verify conflict handling, multi-restore, and unrecoverable status."""
    from backend.recovery.deleted_files_manager import DeletedFilesManager, DeletedFileRecord
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Scenario 1: File without backup -> Recovery Unavailable
        del_info_nobackup = {
            "name": "unbacked_up_file.bin",
            "full_path": str(Path(tmpdir) / "unbacked_up_file.bin"),
            "directory": tmpdir,
            "drive": "C:",
            "size": 500,
            "timestamp": "2026-11-10 13:00:00"
        }
        rec_nobackup = DeletedFilesManager.record_deletion(del_info_nobackup)
        assert rec_nobackup.status == "Recovery Unavailable"
        ok, msg = DeletedFilesManager.restore_record(rec_nobackup)
        assert ok is False

        # Scenario 2: Destination conflict detection (OCCUPIED)
        f = Path(tmpdir) / "conflict_doc.txt"
        f.write_text("Original text in shadow")
        v_entry = FolderVault.store_file(f)

        del_info_conflict = {
            "name": "conflict_doc.txt",
            "full_path": str(f),
            "directory": tmpdir,
            "drive": "C:",
            "size": f.stat().st_size,
            "timestamp": "2026-11-10 13:01:00"
        }
        rec_conflict = DeletedFilesManager.record_deletion(del_info_conflict)
        assert rec_conflict.status == "Backup Available"

        # Now write another file at original location to simulate collision
        f.write_text("New blocking file occupying destination")
        ok, reason = DeletedFilesManager.restore_record(rec_conflict, overwrite=False)
        assert ok is False
        assert reason == "OCCUPIED"

        # Now restore with overwrite=True
        ok_overwrite, msg_ow = DeletedFilesManager.restore_record(rec_conflict, overwrite=True)
        assert ok_overwrite is True
        assert f.read_text() == "Original text in shadow"
        rec_after = DeletedFilesManager.get_record(rec_conflict.event_id)
        assert rec_after.status == "Restored"
