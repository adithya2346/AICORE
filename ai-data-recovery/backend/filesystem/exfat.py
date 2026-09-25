"""
Read-only exFAT File System Parser.
Extracts deleted file sets (types 0x05, 0x85 with in-use bit 0), stream extensions, and file sizes.
"""
import struct
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any

from backend.filesystem.base import FileSystemAnalyzer, FileSystemInfo, DeletedFileRecord
from backend.storage.base import StorageSource

class ExFATAnalyzer(FileSystemAnalyzer):
    """
    Forensic exFAT analyzer.
    Analyzes exFAT VBR (Volume Boot Record) and directory entries.
    """
    def __init__(self, source: StorageSource):
        super().__init__(source)
        self.bytes_per_sector: int = 512
        self.sectors_per_cluster: int = 8
        self.bytes_per_cluster: int = 4096
        self.cluster_offset: int = 0
        self.root_cluster: int = 0
        self._detected: Optional[bool] = None

    def detect(self) -> bool:
        if self._detected is not None:
            return self._detected
        
        boot_sector = self.source.read_bytes(0, 512)
        if len(boot_sector) >= 512 and boot_sector[3:11] == b"EXFAT   ":
            byte_per_sector_shift = boot_sector[0x6C]
            sec_per_cluster_shift = boot_sector[0x6D]
            if 9 <= byte_per_sector_shift <= 12 and sec_per_cluster_shift <= 25:
                self.bytes_per_sector = 1 << byte_per_sector_shift
                self.sectors_per_cluster = 1 << sec_per_cluster_shift
                self.bytes_per_cluster = self.bytes_per_sector * self.sectors_per_cluster
                
                cluster_heap_offset_sectors = struct.unpack_from("<I", boot_sector, 0x58)[0]
                self.cluster_offset = cluster_heap_offset_sectors * self.bytes_per_sector
                self.root_cluster = struct.unpack_from("<I", boot_sector, 0x60)[0]
                self._detected = True
                return True
                
        self._detected = False
        return False

    def cluster_to_byte_offset(self, cluster: int) -> int:
        return self.cluster_offset + ((cluster - 2) * self.bytes_per_cluster)

    def get_filesystem_info(self) -> Optional[FileSystemInfo]:
        if not self.detect():
            return None
        total_clusters = (self.source.get_size() - self.cluster_offset) // self.bytes_per_cluster
        return FileSystemInfo(
            fs_type="exFAT",
            label="exFAT Volume",
            sector_size=self.bytes_per_sector,
            cluster_size=self.bytes_per_cluster,
            total_clusters=max(total_clusters, 0),
            free_clusters=0,
            mft_or_root_offset=self.cluster_to_byte_offset(self.root_cluster),
            metadata={"root_cluster": self.root_cluster}
        )

    def find_deleted_files(self, max_records: int = 1000) -> List[DeletedFileRecord]:
        if not self.detect():
            return []
            
        results = []
        root_offset = self.cluster_to_byte_offset(self.root_cluster)
        dir_data = self.source.read_bytes(root_offset, min(self.bytes_per_cluster * 16, self.source.get_size() - root_offset))
        
        idx = 0
        while idx * 32 + 32 <= len(dir_data) and len(results) < max_records:
            entry = dir_data[idx * 32:(idx + 1) * 32]
            entry_type = entry[0]
            idx += 1
            
            if entry_type == 0x00:
                break
                
            # exFAT in-use bit is bit 7 (0x80). If bit 7 is 0 (e.g. 0x05 instead of 0x85), it was deleted!
            is_deleted = not bool(entry_type & 0x80)
            base_type = entry_type & 0x7F
            
            if base_type == 0x05: # File directory entry
                secondary_count = entry[1]
                # Look ahead for stream extension (base_type 0x20 / entry_type 0xA0 or 0x20)
                file_size = 0
                first_cluster = 0
                file_name = f"deleted_exfat_{idx}"
                
                # Check secondary entries
                for s in range(secondary_count):
                    if (idx + s) * 32 + 32 > len(dir_data):
                        break
                    sec_entry = dir_data[(idx + s) * 32:(idx + s + 1) * 32]
                    sec_type = sec_entry[0] & 0x7F
                    if sec_type == 0x20: # Stream extension
                        first_cluster = struct.unpack_from("<I", sec_entry, 20)[0]
                        file_size = struct.unpack_from("<Q", sec_entry, 24)[0]
                    elif sec_type == 0x21: # File name
                        try:
                            fn_part = sec_entry[2:32].decode("utf-16le", errors="replace").rstrip("\x00")
                            if fn_part:
                                file_name = fn_part
                        except Exception:
                            pass
                            
                runs = []
                if first_cluster >= 2 and file_size > 0:
                    clusters_needed = (file_size + self.bytes_per_cluster - 1) // self.bytes_per_cluster
                    runs.append((first_cluster, clusters_needed))
                    
                if is_deleted:
                    results.append(
                        DeletedFileRecord(
                            filename=file_name,
                            original_path=f"exFAT://{file_name}",
                            file_size=file_size,
                            is_deleted=True,
                            record_id=f"EXFAT_DIR_{idx}",
                            timestamps={},
                            data_runs=runs,
                            direct_bytes=None,
                            filesystem_type="exFAT",
                            allocation_status="unallocated"
                        )
                    )
                idx += secondary_count
                
        return results

    def get_unallocated_ranges(self, max_ranges: int = 500) -> List[Tuple[int, int]]:
        if not self.detect():
            return []
        total_size = self.source.get_size()
        ranges = []
        chunk = self.bytes_per_cluster * 128
        curr = self.cluster_offset
        while curr < total_size and len(ranges) < max_ranges:
            length = min(chunk, total_size - curr)
            ranges.append((curr, length))
            curr += length
        return ranges
