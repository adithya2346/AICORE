"""
Cryptographic hashing utility for forensic evidence handling and fragment verification.
Always ensures read-only streaming to avoid loading large files or disks into memory.
"""
import hashlib
from pathlib import Path
from typing import BinaryIO, Union, Generator, Tuple

BUFFER_SIZE = 64 * 1024  # 64 KB chunks

def calculate_file_sha256(file_path: Union[str, Path], chunk_size: int = BUFFER_SIZE) -> str:
    """Calculate SHA-256 hash of a file on disk using streaming reads."""
    hasher = hashlib.sha256()
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Source file does not exist: {file_path}")
    
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def calculate_bytes_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash of in-memory byte sequence."""
    return hashlib.sha256(data).hexdigest()

def calculate_stream_hashes(stream: BinaryIO, length: int, chunk_size: int = BUFFER_SIZE) -> Tuple[str, str]:
    """Calculate SHA-256 and MD5 hashes over a bounded stream region."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    bytes_read = 0
    
    while bytes_read < length:
        to_read = min(chunk_size, length - bytes_read)
        chunk = stream.read(to_read)
        if not chunk:
            break
        sha256.update(chunk)
        md5.update(chunk)
        bytes_read += len(chunk)
        
    return sha256.hexdigest(), md5.hexdigest()
