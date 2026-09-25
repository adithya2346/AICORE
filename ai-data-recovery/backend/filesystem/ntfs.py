"""
Read-only NTFS File System Parser.
Extracts deleted file records, timestamps, resident data, and non-resident data runs from MFT.
"""
import struct
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple, Dict, Any

from backend.filesystem.base import FileSystemAnalyzer, FileSystemInfo, DeletedFileRecord
from backend.storage.base import StorageSource

def windows_filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows 64-bit 100-nanosecond intervals since Jan 1, 1601 to UTC datetime."""
    if filetime <= 0:
        return None
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return epoch + timedelta(microseconds=filetime // 10)
    except Exception:
        return None

def parse_run_list(run_bytes: bytes) -> List[Tuple[int, int]]:
    """
    Parse NTFS non-resident data run list into (lcn_offset, cluster_count) tuples.
    Each run header byte:
      low nibble = length in bytes of cluster count field
      high nibble = length in bytes of LCN delta field
    """
    runs = []
    i = 0
    current_lcn = 0
    
    while i < len(run_bytes):
        header = run_bytes[i]
        if header == 0:
            break
        i += 1
        
        len_count = header & 0x0F
        len_offset = (header >> 4) & 0x0F
        
        if i + len_count + len_offset > len(run_bytes):
            break
            
        count_bytes = run_bytes[i:i + len_count]
        i += len_count
        count = int.from_bytes(count_bytes, byteorder="little", signed=False)
        
        offset_bytes = run_bytes[i:i + len_offset]
        i += len_offset
        lcn_delta = int.from_bytes(offset_bytes, byteorder="little", signed=True)
        
        current_lcn += lcn_delta
        runs.append((current_lcn, count))
        
    return runs

class NTFSAnalyzer(FileSystemAnalyzer):
    """
    Forensic NTFS analyzer.
    Reads Master File Table (MFT) records without modifying any bytes on disk.
    """
    def __init__(self, source: StorageSource):
        super().__init__(source)
        self.bytes_per_sector: int = 512
        self.sectors_per_cluster: int = 8
        self.bytes_per_cluster: int = 4096
        self.mft_cluster: int = 0
        self.mft_record_size: int = 1024
        self.mft_offset: int = 0
        self._detected: Optional[bool] = None

    def detect(self) -> bool:
        if self._detected is not None:
            return self._detected
        
        # Check boot sector for NTFS OEM ID at offset 3
        boot_sector = self.source.read_bytes(0, 512)
        if len(boot_sector) >= 512 and boot_sector[3:11] == b"NTFS    ":
            self.bytes_per_sector = struct.unpack_from("<H", boot_sector, 0x0B)[0]
            self.sectors_per_cluster = boot_sector[0x0D]
            self.bytes_per_cluster = self.bytes_per_sector * self.sectors_per_cluster
            self.mft_cluster = struct.unpack_from("<q", boot_sector, 0x30)[0]
            
            raw_rec_size = struct.unpack_from("<b", boot_sector, 0x40)[0]
            if raw_rec_size > 0:
                self.mft_record_size = raw_rec_size * self.bytes_per_cluster
            else:
                self.mft_record_size = 1 << (-raw_rec_size)
                
            self.mft_offset = self.mft_cluster * self.bytes_per_cluster
            self._detected = True
            return True
            
        self._detected = False
        return False

    def get_filesystem_info(self) -> Optional[FileSystemInfo]:
        if not self.detect():
            return None
        
        total_clusters = self.source.get_size() // self.bytes_per_cluster
        return FileSystemInfo(
            fs_type="NTFS",
            label="NTFS Volume",
            sector_size=self.bytes_per_sector,
            cluster_size=self.bytes_per_cluster,
            total_clusters=total_clusters,
            free_clusters=0,
            mft_or_root_offset=self.mft_offset,
            metadata={
                "mft_cluster": self.mft_cluster,
                "mft_record_size": self.mft_record_size
            }
        )

    def _apply_fixup(self, record: bytes) -> bytes:
        """Apply NTFS fixup array to reconstruct valid sector ends."""
        if len(record) < self.mft_record_size:
            return record
            
        fixup_offset = struct.unpack_from("<H", record, 4)[0]
        fixup_count = struct.unpack_from("<H", record, 6)[0]
        
        if fixup_offset + (fixup_count * 2) > len(record):
            return record
            
        rec_arr = bytearray(record)
        fixup_key = record[fixup_offset:fixup_offset + 2]
        
        for i in range(1, fixup_count):
            sector_end_offset = (i * self.bytes_per_sector) - 2
            arr_val_offset = fixup_offset + (i * 2)
            if sector_end_offset + 2 <= len(rec_arr):
                # Verify key matches
                if rec_arr[sector_end_offset:sector_end_offset + 2] == fixup_key:
                    rec_arr[sector_end_offset:sector_end_offset + 2] = record[arr_val_offset:arr_val_offset + 2]
                    
        return bytes(rec_arr)

    def parse_mft_record(self, raw_record: bytes, record_idx: int) -> Optional[DeletedFileRecord]:
        """Parse an individual MFT record, checking for deleted status and extracting file attributes."""
        if len(raw_record) < 48:
            return None
            
        # Check signature: 'FILE'
        if raw_record[:4] != b"FILE":
            return None
            
        record = self._apply_fixup(raw_record)
        
        # Flags at 0x16: 0x01 = in-use, 0x02 = directory
        flags = struct.unpack_from("<H", record, 0x16)[0]
        is_in_use = bool(flags & 0x01)
        is_directory = bool(flags & 0x02)
        
        if is_directory:
            return None # Skip directories for file carving
            
        first_attr_offset = struct.unpack_from("<H", record, 0x14)[0]
        curr_offset = first_attr_offset
        
        filename = f"record_{record_idx}"
        file_size = 0
        timestamps: Dict[str, Optional[datetime]] = {}
        data_runs: List[Tuple[int, int]] = []
        direct_bytes: Optional[bytes] = None
        
        # Walk attributes
        while curr_offset + 8 <= len(record):
            attr_type, attr_len = struct.unpack_from("<II", record, curr_offset)
            if attr_type == 0xFFFFFFFF or attr_len == 0:
                break
            if curr_offset + attr_len > len(record):
                break
                
            attr_data = record[curr_offset:curr_offset + attr_len]
            non_resident_flag = attr_data[8]
            
            # $STANDARD_INFORMATION (0x10)
            if attr_type == 0x10 and non_resident_flag == 0:
                content_offset = struct.unpack_from("<H", attr_data, 20)[0]
                if content_offset + 32 <= len(attr_data):
                    cr_time = struct.unpack_from("<q", attr_data, content_offset)[0]
                    mod_time = struct.unpack_from("<q", attr_data, content_offset + 8)[0]
                    timestamps["created"] = windows_filetime_to_datetime(cr_time)
                    timestamps["modified"] = windows_filetime_to_datetime(mod_time)
                    
            # $FILE_NAME (0x30)
            elif attr_type == 0x30 and non_resident_flag == 0:
                content_offset = struct.unpack_from("<H", attr_data, 20)[0]
                fn_body = attr_data[content_offset:]
                if len(fn_body) >= 66:
                    fn_len = fn_body[64]
                    if len(fn_body) >= 66 + (fn_len * 2):
                        try:
                            fn_utf16 = fn_body[66:66 + (fn_len * 2)].decode("utf-16le")
                            if fn_utf16 and not fn_utf16.startswith("$"):
                                filename = fn_utf16
                        except Exception:
                            pass
                            
            # $DATA (0x80)
            elif attr_type == 0x80:
                if non_resident_flag == 0:
                    # Resident data inside MFT record
                    content_size = struct.unpack_from("<I", attr_data, 16)[0]
                    content_offset = struct.unpack_from("<H", attr_data, 20)[0]
                    file_size = content_size
                    if content_offset + content_size <= len(attr_data):
                        direct_bytes = attr_data[content_offset:content_offset + content_size]
                else:
                    # Non-resident data runs
                    file_size = struct.unpack_from("<q", attr_data, 48)[0]
                    run_list_offset = struct.unpack_from("<H", attr_data, 32)[0]
                    if run_list_offset < len(attr_data):
                        raw_runs = attr_data[run_list_offset:]
                        data_runs = parse_run_list(raw_runs)
                        
            curr_offset += attr_len
            
        return DeletedFileRecord(
            filename=filename,
            original_path=f"NTFS://{filename}",
            file_size=file_size,
            is_deleted=not is_in_use,
            record_id=f"MFT_{record_idx}",
            timestamps=timestamps,
            data_runs=data_runs,
            direct_bytes=direct_bytes,
            filesystem_type="NTFS",
            allocation_status="unallocated" if not is_in_use else "allocated"
        )

    def find_deleted_files(self, max_records: int = 1000) -> List[DeletedFileRecord]:
        """Scan the MFT for deleted records."""
        if not self.detect():
            return []
            
        results = []
        # Check first N records in MFT
        record_idx = 0
        while record_idx < max_records:
            offset = self.mft_offset + (record_idx * self.mft_record_size)
            if offset + self.mft_record_size > self.source.get_size():
                break
                
            raw = self.source.read_bytes(offset, self.mft_record_size)
            if not raw or len(raw) < self.mft_record_size:
                break
                
            rec = self.parse_mft_record(raw, record_idx)
            if rec and rec.is_deleted and (rec.file_size > 0 or rec.direct_bytes or rec.data_runs):
                results.append(rec)
                
            record_idx += 1
            
        return results

    def get_unallocated_ranges(self, max_ranges: int = 500) -> List[Tuple[int, int]]:
        """Return potential unallocated space ranges based on non-MFT areas."""
        if not self.detect():
            return []
        # Fallback to returning areas beyond MFT start
        total_size = self.source.get_size()
        ranges = []
        chunk = self.bytes_per_cluster * 1024
        curr = max(self.mft_offset + (1024 * 1024), 0)
        while curr < total_size and len(ranges) < max_ranges:
            length = min(chunk, total_size - curr)
            ranges.append((curr, length))
            curr += length
        return ranges
