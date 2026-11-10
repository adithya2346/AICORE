"""
System-Wide Windows Storage Device Discovery & Partition Enumeration.
Uses native Windows APIs (GetLogicalDrives, GetDriveTypeW, GetVolumeInformationW, GetDiskFreeSpaceExW)
to detect, categorize, and inspect all internal SSDs, HDDs, external drives, and USB flash drives.
"""
from __future__ import annotations

import os
import sys
import ctypes
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


DRIVE_TYPE_MAP = {
    0: ("UNKNOWN", "Unknown Drive"),
    1: ("NO_ROOT_DIR", "Invalid Root"),
    2: ("REMOVABLE", "USB Flash / Removable"),
    3: ("FIXED", "Fixed Storage (SSD/HDD)"),
    4: ("REMOTE", "Network Drive"),
    5: ("CDROM", "Optical Drive (CD/DVD)"),
    6: ("RAMDISK", "RAM Disk"),
}


@dataclass
class StorageDevice:
    drive_letter: str             # e.g., "C:"
    root_path: str                # e.g., "C:\\"
    volume_name: str              # e.g., "ACER" or "USB_DATA"
    filesystem: str               # e.g., "NTFS", "FAT32", "exFAT"
    drive_type_code: int          # Windows code (2=removable, 3=fixed, etc.)
    drive_type_desc: str          # Descriptive string
    is_system: bool               # True if contains Windows directory
    is_removable: bool            # True if USB / removable
    is_accessible: bool           # True if volume is mounted & readable
    total_bytes: int = 0
    free_bytes: int = 0
    status: str = "detected"      # "detected", "monitoring", "paused", "disconnected"

    @property
    def total_gb(self) -> float:
        return round(self.total_bytes / (1024 ** 3), 1)

    @property
    def free_gb(self) -> float:
        return round(self.free_bytes / (1024 ** 3), 1)

    @property
    def used_gb(self) -> float:
        return round(max(0, self.total_bytes - self.free_bytes) / (1024 ** 3), 1)

    @property
    def used_percentage(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return round((1.0 - (self.free_bytes / self.total_bytes)) * 100.0, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drive_letter": self.drive_letter,
            "root_path": self.root_path,
            "volume_name": self.volume_name,
            "filesystem": self.filesystem,
            "drive_type_code": self.drive_type_code,
            "drive_type_desc": self.drive_type_desc,
            "is_system": self.is_system,
            "is_removable": self.is_removable,
            "is_accessible": self.is_accessible,
            "total_bytes": self.total_bytes,
            "free_bytes": self.free_bytes,
            "total_gb": self.total_gb,
            "free_gb": self.free_gb,
            "used_gb": self.used_gb,
            "used_percentage": self.used_percentage,
            "status": self.status,
        }


class StorageDeviceDetector:
    """Discovers and monitors all eligible storage volumes across the Windows system."""

    @staticmethod
    def get_system_drive_letter() -> str:
        win_dir = os.environ.get("SystemRoot", "C:\\Windows")
        return win_dir[:2].upper()

    @classmethod
    def enumerate_drives(cls) -> List[StorageDevice]:
        """
        Enumerate all active logical drives and partitions using Windows kernel APIs.
        Filters out CD/DVD drives and inaccessible drives.
        """
        devices: List[StorageDevice] = []
        if sys.platform != "win32":
            # POSIX fallback
            devices.append(StorageDevice(
                drive_letter="/",
                root_path="/",
                volume_name="Root",
                filesystem="ext4",
                drive_type_code=3,
                drive_type_desc="System Root",
                is_system=True,
                is_removable=False,
                is_accessible=True,
                total_bytes=500 * 1024**3,
                free_bytes=250 * 1024**3,
                status="ready"
            ))
            return devices

        kernel32 = ctypes.windll.kernel32
        bitmask = kernel32.GetLogicalDrives()
        system_drive = cls.get_system_drive_letter()

        for i in range(26):
            mask = 1 << i
            if bitmask & mask:
                drive_letter = f"{chr(65 + i)}:"
                root_path = f"{drive_letter}\\"
                dtype = kernel32.GetDriveTypeW(root_path)

                # Exclude CD-ROM drives (5) and invalid root paths (1)
                if dtype in (1, 5):
                    continue

                type_key, type_desc = DRIVE_TYPE_MAP.get(dtype, ("UNKNOWN", "Generic Storage"))
                is_system = (drive_letter.upper() == system_drive.upper())
                is_removable = (dtype == 2)

                if is_system:
                    type_desc = "SSD (System)"
                elif dtype == 3:
                    type_desc = "Fixed Storage (SSD/HDD)"
                elif dtype == 2:
                    type_desc = "USB Flash / Removable"

                # Query Volume Information
                volume_name_buf = ctypes.create_unicode_buffer(261)
                fs_name_buf = ctypes.create_unicode_buffer(261)
                serial_num = ctypes.c_ulong()
                max_len = ctypes.c_ulong()
                flags = ctypes.c_ulong()

                res = kernel32.GetVolumeInformationW(
                    root_path,
                    volume_name_buf, 261,
                    ctypes.byref(serial_num),
                    ctypes.byref(max_len),
                    ctypes.byref(flags),
                    fs_name_buf, 261
                )

                if not res:
                    # Inaccessible or unformatted drive
                    continue

                volume_label = volume_name_buf.value or ("Windows" if is_system else f"Local Disk ({drive_letter})")
                fs_type = fs_name_buf.value or "NTFS"

                # Query capacity
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                total_free = ctypes.c_ulonglong(0)

                space_res = kernel32.GetDiskFreeSpaceExW(
                    root_path,
                    ctypes.byref(free_bytes),
                    ctypes.byref(total_bytes),
                    ctypes.byref(total_free)
                )

                tot_b = total_bytes.value if space_res else 0
                fr_b = free_bytes.value if space_res else 0

                devices.append(StorageDevice(
                    drive_letter=drive_letter,
                    root_path=root_path,
                    volume_name=volume_label,
                    filesystem=fs_type,
                    drive_type_code=dtype,
                    drive_type_desc=type_desc,
                    is_system=is_system,
                    is_removable=is_removable,
                    is_accessible=True,
                    total_bytes=tot_b,
                    free_bytes=fr_b,
                    status="ready"
                ))

        return devices

