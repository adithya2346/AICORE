"""
Forensic File Carver.
Associates discovered header and footer hits with boundary heuristics to isolate candidate files.
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any

from backend.storage.base import StorageSource
from backend.recovery.scanner import RawStorageScanner, RawScanReport, ScanHit
from backend.recovery.signatures import SIGNATURE_DATABASE, FileSignature
from backend.recovery.fragments import Fragment, slice_bytes_into_fragments

@dataclass
class CarvedCandidate:
    candidate_id: str
    format_name: str
    start_offset: int
    end_offset: int
    estimated_size: int
    data: bytes
    has_valid_header: bool
    has_valid_footer: bool
    is_fragmented: bool
    confidence: float
    fragments: List[Fragment]

class FileCarver:
    """
    Carves files from raw storage scanning results.
    """
    def __init__(self, source: StorageSource):
        self.source = source

    def carve_from_scan(self, scan_report: RawScanReport, job_id: str, fragment_size: int = 4096) -> List[CarvedCandidate]:
        candidates: List[CarvedCandidate] = []
        c_idx = 1
        
        # Group headers by format
        headers_by_format: Dict[str, List[ScanHit]] = {}
        for h in scan_report.header_hits:
            headers_by_format.setdefault(h.format_name, []).append(h)
            
        footers_by_format: Dict[str, List[ScanHit]] = {}
        for f in scan_report.footer_hits:
            footers_by_format.setdefault(f.format_name, []).append(f)
            
        for fmt_name, headers in headers_by_format.items():
            footers = footers_by_format.get(fmt_name, [])
            # Find signature spec
            sig = next((s for s in SIGNATURE_DATABASE if s.format_name == fmt_name), None)
            max_dist = sig.footer_search_max_distance if sig else 20 * 1024 * 1024
            min_size = sig.min_size if sig else 128
            
            for h in headers:
                start_off = h.offset
                # Find matching footer after start_off within max_dist
                matching_footers = [f for f in footers if f.offset > start_off and (f.offset - start_off) <= max_dist]
                
                if matching_footers:
                    # Choose first matching footer after header that satisfies min_size
                    chosen_footer = None
                    for mf in matching_footers:
                        ft_len = len(sig.footer_bytes) if (sig and sig.footer_bytes) else 2
                        potential_end = mf.offset + ft_len
                        if potential_end - start_off >= min_size:
                            chosen_footer = mf
                            break
                    
                    if chosen_footer:
                        ft_len = len(sig.footer_bytes) if (sig and sig.footer_bytes) else 2
                        end_off = chosen_footer.offset + ft_len
                        raw_data = self.source.read_bytes(start_off, end_off - start_off)
                        
                        frags = slice_bytes_into_fragments(
                            raw_data,
                            job_id=job_id,
                            base_offset=start_off,
                            fragment_size=fragment_size,
                            prefix_id=f"carve_{c_idx}"
                        )
                        if frags:
                            frags[0].is_header = True
                            frags[-1].is_footer = True
                            
                        candidates.append(
                            CarvedCandidate(
                                candidate_id=f"CARVE-{fmt_name.upper()}-{c_idx:03d}",
                                format_name=fmt_name,
                                start_offset=start_off,
                                end_offset=end_off,
                                estimated_size=len(raw_data),
                                data=raw_data,
                                has_valid_header=True,
                                has_valid_footer=True,
                                is_fragmented=False,
                                confidence=0.85,
                                fragments=frags
                            )
                        )
                        c_idx += 1
                        continue
                        
                # If no footer found (e.g. truncated or format without standard footer like MP4/SQLite)
                fallback_size = min(max_dist, 512 * 1024) # Carve reasonable block
                raw_data = self.source.read_bytes(start_off, fallback_size)
                if len(raw_data) >= min_size:
                    frags = slice_bytes_into_fragments(
                        raw_data,
                        job_id=job_id,
                        base_offset=start_off,
                        fragment_size=fragment_size,
                        prefix_id=f"carve_{c_idx}"
                    )
                    if frags:
                        frags[0].is_header = True
                    candidates.append(
                        CarvedCandidate(
                            candidate_id=f"CARVE-{fmt_name.upper()}-{c_idx:03d}",
                            format_name=fmt_name,
                            start_offset=start_off,
                            end_offset=start_off + len(raw_data),
                            estimated_size=len(raw_data),
                            data=raw_data,
                            has_valid_header=True,
                            has_valid_footer=False,
                            is_fragmented=True,
                            confidence=0.45,
                            fragments=frags
                        )
                    )
                    c_idx += 1
                    
        return candidates
