"""
PartitionSource represents a defined partition slice within a larger disk image or device.
"""
from pathlib import Path
from typing import Dict, Any, Optional
from backend.storage.base import StorageSource

class PartitionSource(StorageSource):
    """
    Sub-source representing a specific partition slice bounded by [offset, offset + size).
    """
    def __init__(
        self,
        underlying_source: StorageSource,
        partition_offset: int,
        partition_size: int,
        partition_type: str = "unknown",
        partition_index: int = 0
    ):
        self.underlying_source = underlying_source
        self.partition_offset = partition_offset
        self.partition_size = partition_size
        self.partition_type = partition_type
        self.partition_index = partition_index
        self.source_path = underlying_source.source_path
        self._is_open = False
        self._sha256 = None
        self._size = partition_size

    def open(self) -> "PartitionSource":
        self.underlying_source.open()
        self._is_open = True
        return self

    def close(self) -> None:
        self._is_open = False

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset >= self.partition_size:
            return b""
        actual_offset = self.partition_offset + offset
        actual_len = min(length, self.partition_size - offset)
        return self.underlying_source.read_bytes(actual_offset, actual_len)

    def get_size(self) -> int:
        return self.partition_size

    def get_sector_size(self) -> int:
        return self.underlying_source.get_sector_size()

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "source_type": "partition",
            "partition_index": self.partition_index,
            "partition_offset": self.partition_offset,
            "partition_size": self.partition_size,
            "partition_type": self.partition_type,
            "underlying_path": str(self.source_path.resolve()),
            "read_only": True
        }
