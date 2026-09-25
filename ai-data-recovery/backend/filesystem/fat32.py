"""
Read-only FAT32 File System Parser.
Extracts deleted directory entries marked with 0xE5, timestamps, and cluster chains.
"""
import struct
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any

from backend.filesystem.base import FileSystemAnalyzer, FileSystemInfo, DeletedFileRecord
from backend.storage.base import StorageSource

def fat_datetime_to_dt(fat_date: int, fat_time: int) -> Optional[datetime]:
    """Convert MS-DOS date and time bitfields to UTC datetime."""
    try:
        year = ((fat_date >> 9) & 0x7F) + 1980
        month = (fat_date >> 5) & 0x0F
        day = fat_date & 0x1F
        hour = (fat_time >> 11) & 0x1F
        minute = (fat_time >> 5) & 0x3F
        second = (fat_time & 0x1F) * 2
        if month < 1 or month > 12 or day < 1 or day > 31:
            return None
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except Exception:
        return None

class FAT32Analyzer(FileSystemAnalyzer):
    """
    Forensic FAT32 analyzer.
    Detects deleted entries (first byte == 0xE5) in directory clusters.
    """
    def __init__(self, source: StorageSource):
        super().__init__(source)
        self.bytes_per_sector: int = 512
        self.sectors_per_cluster: int = 8
        self.bytes_per_cluster: int = 4096
        self.reserved_sectors: int = 32
        self.num_fats: int = 2
        self.sectors_per_fat: int = 0
        self.root_cluster: int = 2
        self.data_area_offset: int = 0
        self._detected: Optional[bool] = None

    def detect(self) -> bool:
        if self._detected is not None:
            return self._detected
        
        boot_sector = self.source.read_bytes(0, 512)
        if len(boot_sector) >= 512 and boot_sector[510:512] == b"\x55\xaa":
            # FAT32 has 'FAT32   ' at offset 0x52 or jump instruction at 0
            fat_str = boot_sector[0x52:0x5A]
            if b"FAT32" in fat_str or (boot_sector[0] in (0xEB, 0xE9) and boot_sector[0x10] in (1, 2)):
                bps = struct.unpack_from("<H", boot_sector, 0x0B)[0]
                spc = boot_sector[0x0D]
                if bps in (512, 1024, 2048, 4096) and spc > 0:
                    self.bytes_per_sector = bps
                    self.sectors_per_cluster = spc
                    self.bytes_per_cluster = bps * spc
                    self.reserved_sectors = struct.unpack_from("<H", boot_sector, 0x0E)[0]
                    self.num_fats = boot_sector[0x10]
                    self.sectors_per_fat = struct.unpack_from("<I", boot_sector, 0x24)[0]
                    self.root_cluster = struct.unpack_from("<I", boot_sector, 0x2C)[0]
                    
                    fat_size_bytes = self.num_fats * self.sectors_per_fat * self.bytes_per_sector
                    self.data_area_offset = (self.reserved_sectors * self.bytes_per_sector) + fat_size_bytes
                    self._detected = True
                    return True
                    
        self._detected = False
        return False

    def cluster_to_byte_offset(self, cluster: int) -> int:
        """Convert a cluster number (>=2) to an absolute byte offset."""
        return self.data_area_offset + ((cluster - 2) * self.bytes_per_cluster)

    def get_filesystem_info(self) -> Optional[FileSystemInfo]:
        if not self.detect():
            return None
        total_clusters = (self.source.get_size() - self.data_area_offset) // self.bytes_per_cluster
        return FileSystemInfo(
            fs_type="FAT32",
            label="FAT32 Volume",
            sector_size=self.bytes_per_sector,
            cluster_size=self.bytes_per_cluster,
            total_clusters=max(total_clusters, 0),
            free_clusters=0,
            mft_or_root_offset=self.cluster_to_byte_offset(self.root_cluster),
            metadata={"root_cluster": self.root_cluster}
        )

    def find_deleted_files(self, max_records: int = 1000) -> List[DeletedFileRecord]:
        """Search the root directory and subsequent clusters for deleted entries (0xE5 prefix)."""
        if not self.detect():
            return []
            
        results = []
        root_offset = self.cluster_to_byte_offset(self.root_cluster)
        dir_bytes = self.source.read_bytes(root_offset, min(self.bytes_per_cluster * 16, self.source.get_size() - root_offset))
        
        entry_idx = 0
        while entry_idx * 32 + 32 <= len(dir_bytes) and len(results) < max_records:
            entry = dir_bytes[entry_idx * 32:(entry_idx + 1) * 32]
            entry_idx += 1
            
            first_byte = entry[0]
            if first_byte == 0x00:
                # End of directory
                break
                
            attr = entry[11]
            if attr == 0x0F:
                # LFN entry, skip or parse
                continue
                
            is_deleted = (first_byte == 0xE5)
            if is_deleted:
                raw_name = entry[1:8]
                raw_ext = entry[8:11]
                try:
                    name_str = "_" + raw_name.decode("ascii", errors="replace").strip()
                    ext_str = raw_ext.decode("ascii", errors="replace").strip()
                    full_name = f"{name_str}.{ext_str}" if ext_str else name_str
                except Exception:
                    full_name = f"deleted_fat32_{entry_idx}"
                    
                clust_high = struct.unpack_from("<H", entry, 20)[0]
                clust_low = struct.unpack_from("<H", entry, 26)[0]
                start_cluster = (clust_high << 16) | clust_low
                file_size = struct.unpack_from("<I", entry, 28)[0]
                
                fat_date = struct.unpack_from("<H", entry, 24)[0]
                fat_time = struct.unpack_from("<H", entry, 22)[0]
                mod_dt = fat_datetime_to_dt(fat_date, fat_time)
                
                runs = []
                if start_cluster >= 2 and file_size > 0:
                    clusters_needed = (file_size + self.bytes_per_cluster - 1) // self.bytes_per_cluster
                    # Starting contiguous run assumption for deleted FAT32 files
                    runs.append((start_cluster, clusters_needed))
                    
                results.append(
                    DeletedFileRecord(
                        filename=full_name,
                        original_path=f"FAT32://{full_name}",
                        file_size=file_size,
                        is_deleted=True,
                        record_id=f"FAT32_DIR_{entry_idx}",
                        timestamps={"modified": mod_dt},
                        data_runs=runs,
                        direct_bytes=None,
                        filesystem_type="FAT32",
                        allocation_status="unallocated"
                    )
                )
                
        return results

    def get_unallocated_ranges(self, max_ranges: int = 500) -> List[Tuple[int, int]]:
        if not self.detect():
            return []
        total_size = self.source.get_size()
        ranges = []
        chunk = self.bytes_per_cluster * 128
        curr = self.data_area_offset
        while curr < total_size and len(ranges) < max_ranges:
            length = min(chunk, total_size - curr)
            ranges.append((curr, length))
            curr += length
        return ranges
