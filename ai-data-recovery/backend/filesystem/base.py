"""
Base interface and dataclasses for read-only filesystem analysis.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

from backend.storage.base import StorageSource

@dataclass
class DeletedFileRecord:
    """Represents a discovered deleted or remnants file record from filesystem metadata."""
    filename: str
    original_path: str
    file_size: int
    is_deleted: bool
    record_id: str
    timestamps: Dict[str, Optional[datetime]] = field(default_factory=dict)
    data_runs: List[Tuple[int, int]] = field(default_factory=list) # (cluster_offset, cluster_count)
    direct_bytes: Optional[bytes] = None # For resident data attributes
    filesystem_type: str = "unknown"
    allocation_status: str = "unallocated"

@dataclass
class FileSystemInfo:
    fs_type: str
    label: str
    sector_size: int
    cluster_size: int
    total_clusters: int
    free_clusters: int
    mft_or_root_offset: int
    metadata: Dict[str, Any] = field(default_factory=dict)

class FileSystemAnalyzer(ABC):
    """
    Abstract read-only filesystem parser.
    Never writes to or modifies the underlying storage.
    """
    def __init__(self, source: StorageSource):
        self.source = source

    @abstractmethod
    def detect(self) -> bool:
        """Return True if this filesystem matches the storage source."""
        pass

    @abstractmethod
    def get_filesystem_info(self) -> Optional[FileSystemInfo]:
        """Return structural parameters of the filesystem."""
        pass

    @abstractmethod
    def find_deleted_files(self, max_records: int = 1000) -> List[DeletedFileRecord]:
        """Scan filesystem metadata for deleted file remnants."""
        pass

    @abstractmethod
    def get_unallocated_ranges(self, max_ranges: int = 500) -> List[Tuple[int, int]]:
        """Return byte offset ranges representing unallocated clusters."""
        pass
