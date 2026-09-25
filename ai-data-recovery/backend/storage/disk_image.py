"""
DiskImageSource implementation for forensic disk images (.dd, .raw, .img).
Supports reading MBR partition tables and discovering partition slices.
"""
from pathlib import Path
from typing import Optional, List, Dict, Any, BinaryIO
import struct

from backend.storage.base import StorageSource
from backend.storage.partition import PartitionSource

class DiskImageSource(StorageSource):
    """
    Forensic disk image reader with MBR partition table discovery.
    """
    def __init__(self, source_path: Path, sector_size: int = 512):
        super().__init__(source_path)
        self.sector_size = sector_size
        self._file_handle: Optional[BinaryIO] = None
        self._size = self.source_path.stat().st_size
        self._partitions: Optional[List[PartitionSource]] = None

    def open(self) -> "DiskImageSource":
        if self._file_handle is None or self._file_handle.closed:
            self._file_handle = open(self.source_path, "rb")
            self._is_open = True
        return self

    def close(self) -> None:
        if self._file_handle and not self._file_handle.closed:
            self._file_handle.close()
            self._file_handle = None
            self._is_open = False

    def read_bytes(self, offset: int, length: int) -> bytes:
        if not self._is_open or not self._file_handle:
            self.open()
        
        if offset >= self._size:
            return b""
        
        self._file_handle.seek(offset)
        return self._file_handle.read(length)

    def get_size(self) -> int:
        return self._size

    def get_sector_size(self) -> int:
        return self.sector_size

    def discover_partitions(self) -> List[PartitionSource]:
        """
        Parses Master Boot Record (MBR) at sector 0 to locate partitions.
        Falls back to treating the entire image as a single partition if no MBR signature exists.
        """
        if self._partitions is not None:
            return self._partitions
        
        self.open()
        mbr_data = self.read_bytes(0, 512)
        partitions = []
        
        # Check MBR boot signature 0x55AA at offset 510
        if len(mbr_data) == 512 and mbr_data[510:512] == b"\x55\xaa":
            # 4 primary partition table entries starting at 446 (0x1BE), 16 bytes each
            for i in range(4):
                entry_offset = 446 + (i * 16)
                entry = mbr_data[entry_offset:entry_offset + 16]
                
                status, chs_first, part_type, chs_last, lba_start, num_sectors = struct.unpack(
                    "<B3sB3sII", entry
                )
                
                if part_type != 0 and num_sectors > 0:
                    byte_offset = lba_start * self.sector_size
                    byte_size = num_sectors * self.sector_size
                    
                    # Verify partition fits within the disk image
                    if byte_offset + byte_size <= self._size:
                        type_str = "unknown"
                        if part_type == 0x07:
                            type_str = "NTFS/exFAT"
                        elif part_type in (0x0B, 0x0C):
                            type_str = "FAT32"
                        elif part_type == 0x83:
                            type_str = "Linux"
                            
                        part_source = PartitionSource(
                            underlying_source=self,
                            partition_offset=byte_offset,
                            partition_size=byte_size,
                            partition_type=type_str,
                            partition_index=i + 1
                        )
                        partitions.append(part_source)
        
        # If no partitions discovered via MBR, check if the image itself is a raw partition
        if not partitions:
            # Check for direct filesystem boot records (e.g. NTFS OEM ID 'NTFS    ' at offset 3)
            direct_type = "raw_image"
            if len(mbr_data) >= 8:
                if mbr_data[3:11] == b"NTFS    ":
                    direct_type = "NTFS"
                elif mbr_data[3:11] == b"EXFAT   ":
                    direct_type = "exFAT"
                elif b"MSDOS" in mbr_data[3:11] or b"FAT32" in self.read_bytes(0x52, 5):
                    direct_type = "FAT32"
            
            partitions.append(
                PartitionSource(
                    underlying_source=self,
                    partition_offset=0,
                    partition_size=self._size,
                    partition_type=direct_type,
                    partition_index=1
                )
            )
            
        self._partitions = partitions
        return partitions

    def get_metadata(self) -> Dict[str, Any]:
        parts = self.discover_partitions()
        return {
            "source_type": "disk_image",
            "file_name": self.source_path.name,
            "path": str(self.source_path.resolve()),
            "size": self._size,
            "sector_size": self.sector_size,
            "partition_count": len(parts),
            "partitions": [p.get_metadata() for p in parts],
            "read_only": True
        }
