"""
Base storage abstraction layer for digital evidence sources.
Enforces strictly READ-ONLY access to preserve forensic integrity.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List, Dict, Any, BinaryIO
import hashlib

class StorageSource(ABC):
    """
    Abstract interface for all forensic evidence storage sources.
    Guarantees read-only streaming access to preserve evidence integrity.
    """
    def __init__(self, source_path: Path):
        self.source_path = Path(source_path)
        if not self.source_path.exists():
            raise FileNotFoundError(f"Storage source does not exist: {self.source_path}")
        self._is_open = False
        self._sha256: Optional[str] = None
        self._size: Optional[int] = None

    @abstractmethod
    def open(self) -> "StorageSource":
        """Open source handle in strictly read-only mode."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close open file handles."""
        pass

    def __enter__(self) -> "StorageSource":
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @abstractmethod
    def read_bytes(self, offset: int, length: int) -> bytes:
        """Read arbitrary byte slice starting from offset."""
        pass

    @abstractmethod
    def get_size(self) -> int:
        """Total size in bytes of the storage source."""
        pass

    @abstractmethod
    def get_sector_size(self) -> int:
        """Sector/block size, defaults to 512 bytes."""
        return 512

    def calculate_sha256(self, chunk_size: int = 64 * 1024) -> str:
        """Calculate forensic SHA-256 hash using streaming reads."""
        if self._sha256:
            return self._sha256
        
        hasher = hashlib.sha256()
        total_size = self.get_size()
        offset = 0
        
        while offset < total_size:
            to_read = min(chunk_size, total_size - offset)
            chunk = self.read_bytes(offset, to_read)
            if not chunk:
                break
            hasher.update(chunk)
            offset += len(chunk)
            
        self._sha256 = hasher.hexdigest()
        return self._sha256

    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """Return technical metadata about the storage source."""
        pass
