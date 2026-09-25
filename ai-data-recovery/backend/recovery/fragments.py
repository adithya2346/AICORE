"""
Fragment Representation and Feature Extraction for AI/ML Processing.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import List, Dict, Any, Optional

from backend.recovery.scanner import calculate_entropy

@dataclass
class Fragment:
    fragment_id: str
    job_id: str
    source_offset: int
    length: int
    data: bytes
    sha256: str = ""
    entropy: float = 0.0
    byte_histogram: List[int] = field(default_factory=lambda: [0] * 256)
    n_gram_features: Dict[str, float] = field(default_factory=dict)
    format_features: Dict[str, Any] = field(default_factory=dict)
    source_region: str = "unallocated"
    creation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "valid" # valid, corrupted, duplicate, unrelated, incomplete
    predicted_type: str = "unknown"
    type_probabilities: Dict[str, float] = field(default_factory=dict)
    is_header: bool = False
    is_footer: bool = False

    def __post_init__(self):
        if not self.sha256 and self.data:
            self.sha256 = hashlib.sha256(self.data).hexdigest()
        if self.entropy == 0.0 and self.data:
            self.entropy = calculate_entropy(self.data)
        if not any(self.byte_histogram) and self.data:
            self._compute_histogram()

    def _compute_histogram(self):
        hist = [0] * 256
        for b in self.data:
            hist[b] += 1
        self.byte_histogram = hist

    @property
    def prefix_bytes(self) -> bytes:
        return self.data[:32] if self.data else b""

    @property
    def suffix_bytes(self) -> bytes:
        return self.data[-32:] if self.data else b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fragment_id": self.fragment_id,
            "job_id": self.job_id,
            "source_offset": self.source_offset,
            "length": self.length,
            "sha256": self.sha256,
            "entropy": round(self.entropy, 4),
            "status": self.status,
            "predicted_type": self.predicted_type,
            "type_probabilities": self.type_probabilities,
            "is_header": self.is_header,
            "is_footer": self.is_footer,
            "source_region": self.source_region
        }

def slice_bytes_into_fragments(
    raw_data: bytes,
    job_id: str,
    base_offset: int = 0,
    fragment_size: int = 4096,
    prefix_id: str = "frag"
) -> List[Fragment]:
    """
    Utility to partition arbitrary raw data or carved region into standard fragments.
    """
    fragments: List[Fragment] = []
    total_len = len(raw_data)
    idx = 0
    curr = 0
    
    while curr < total_len:
        chunk_len = min(fragment_size, total_len - curr)
        chunk = raw_data[curr:curr + chunk_len]
        frag_id = f"{prefix_id}_{idx:04d}"
        
        frag = Fragment(
            fragment_id=frag_id,
            job_id=job_id,
            source_offset=base_offset + curr,
            length=chunk_len,
            data=chunk
        )
        fragments.append(frag)
        curr += chunk_len
        idx += 1
        
    return fragments
