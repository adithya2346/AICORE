"""
FileSource implementation for individual files, uploaded evidence, and single damaged files.
"""
from pathlib import Path
from typing import Optional, Dict, Any, BinaryIO
import os

from backend.storage.base import StorageSource

class FileSource(StorageSource):
    """
    Forensic storage source for individual uploaded or local damaged files.
    """
    def __init__(self, source_path: Path):
        super().__init__(source_path)
        self._file_handle: Optional[BinaryIO] = None
        self._size = self.source_path.stat().st_size

    def open(self) -> "FileSource":
        if self._file_handle is None or self._file_handle.closed:
            # strictly 'rb' read-only binary mode
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
        return 512

    def get_metadata(self) -> Dict[str, Any]:
        stat = self.source_path.stat()
        return {
            "source_type": "file",
            "file_name": self.source_path.name,
            "path": str(self.source_path.resolve()),
            "size": self._size,
            "modified_time": stat.st_mtime,
            "read_only": True
        }
