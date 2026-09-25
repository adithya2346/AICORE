"""
Streaming Raw Storage Scanner and File Carver.
Scans physical drives, partitions, or forensic disk images for file signatures,
boundary markers, and Shannon entropy distributions with cancellation and progress reporting.
"""
import math
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Any
import hashlib

from backend.storage.base import StorageSource
from backend.recovery.signatures import SIGNATURE_DATABASE, FileSignature

def calculate_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy (0.0 to 8.0 bits per byte).
    0.0 = uniform single byte (e.g., all zeroes or nulls)
    8.0 = high disorder (e.g., compressed or encrypted streams)
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy

@dataclass
class ScanHit:
    offset: int
    format_name: str
    marker_type: str # 'header', 'footer', 'structural'
    signature: bytes
    entropy: float
    sha256_block: str
    surrounding_preview: bytes = b""

@dataclass
class RawScanReport:
    source_size: int
    bytes_scanned: int
    total_hits: int
    header_hits: List[ScanHit] = field(default_factory=list)
    footer_hits: List[ScanHit] = field(default_factory=list)
    structural_hits: List[ScanHit] = field(default_factory=list)
    entropy_profile: List[Dict[str, Any]] = field(default_factory=list)

class RawStorageScanner:
    """
    Performs chunked, low-memory raw disk/image scanning.
    """
    def __init__(self, source: StorageSource, block_size: int = 4096, scan_chunk_size: int = 1024 * 1024):
        self.source = source
        self.block_size = block_size
        self.scan_chunk_size = scan_chunk_size
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def scan(
        self,
        start_offset: int = 0,
        max_bytes: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> RawScanReport:
        """
        Execute raw scan across the specified byte range.
        Never loads the entire storage into RAM.
        """
        self.source.open()
        total_size = self.source.get_size()
        scan_limit = min(max_bytes or total_size, total_size - start_offset)
        
        report = RawScanReport(source_size=total_size, bytes_scanned=0, total_hits=0)
        curr_offset = start_offset
        bytes_scanned = 0
        
        # Keep an overlap buffer to catch signatures spanning chunk boundaries
        overlap_size = 128
        prev_tail = b""
        
        while bytes_scanned < scan_limit and not self._cancelled:
            to_read = min(self.scan_chunk_size, scan_limit - bytes_scanned)
            chunk = self.source.read_bytes(curr_offset, to_read)
            if not chunk:
                break
                
            combined = prev_tail + chunk
            combined_base_offset = curr_offset - len(prev_tail)
            
            # Check signatures in combined block
            for sig in SIGNATURE_DATABASE:
                # 1. Header search
                pos = 0
                while True:
                    idx = combined.find(sig.magic_bytes, pos)
                    if idx == -1:
                        break
                    hit_offset = combined_base_offset + idx - sig.magic_offset
                    if hit_offset >= 0:
                        block_slice = combined[max(0, idx - 16):min(len(combined), idx + 64)]
                        report.header_hits.append(
                            ScanHit(
                                offset=hit_offset,
                                format_name=sig.format_name,
                                marker_type="header",
                                signature=sig.magic_bytes,
                                entropy=calculate_entropy(block_slice),
                                sha256_block=hashlib.sha256(block_slice).hexdigest(),
                                surrounding_preview=block_slice[:32]
                            )
                        )
                    pos = idx + 1
                    
                # 2. Footer search
                if sig.footer_bytes:
                    pos = 0
                    while True:
                        idx = combined.find(sig.footer_bytes, pos)
                        if idx == -1:
                            break
                        hit_offset = combined_base_offset + idx
                        if hit_offset >= 0:
                            block_slice = combined[max(0, idx - 16):min(len(combined), idx + len(sig.footer_bytes) + 16)]
                            report.footer_hits.append(
                                ScanHit(
                                    offset=hit_offset,
                                    format_name=sig.format_name,
                                    marker_type="footer",
                                    signature=sig.footer_bytes,
                                    entropy=calculate_entropy(block_slice),
                                    sha256_block=hashlib.sha256(block_slice).hexdigest(),
                                    surrounding_preview=block_slice[:32]
                                )
                            )
                        pos = idx + 1
                        
            # Record periodic entropy sampling
            if bytes_scanned % (512 * 1024) == 0:
                sample_entropy = calculate_entropy(chunk[:min(len(chunk), 4096)])
                report.entropy_profile.append({
                    "offset": curr_offset,
                    "entropy": round(sample_entropy, 3)
                })
                
            prev_tail = chunk[-overlap_size:] if len(chunk) >= overlap_size else chunk
            curr_offset += len(chunk)
            bytes_scanned += len(chunk)
            report.bytes_scanned = bytes_scanned
            
            if progress_callback:
                pct = int((bytes_scanned / max(scan_limit, 1)) * 100)
                progress_callback(bytes_scanned, scan_limit, f"Scanning raw sectors ({pct}%)")
                
        report.total_hits = len(report.header_hits) + len(report.footer_hits) + len(report.structural_hits)
        return report
