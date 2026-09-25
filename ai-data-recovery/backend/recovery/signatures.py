"""
File signature database and binary structural markers for digital forensics.
Covers: JPEG, PNG, PDF, ZIP, DOCX, XLSX, MP4, MP3, SQLite.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any

@dataclass
class FileSignature:
    format_name: str
    extensions: List[str]
    magic_bytes: bytes
    magic_offset: int = 0
    footer_bytes: Optional[bytes] = None
    footer_search_max_distance: int = 50 * 1024 * 1024 # 50 MB max carve limit
    min_size: int = 64
    structural_markers: List[bytes] = field(default_factory=list)
    description: str = ""

SIGNATURE_DATABASE: List[FileSignature] = [
    # JPEG / JFIF / EXIF
    FileSignature(
        format_name="jpeg",
        extensions=["jpg", "jpeg"],
        magic_bytes=b"\xFF\xD8\xFF",
        magic_offset=0,
        footer_bytes=b"\xFF\xD9",
        footer_search_max_distance=30 * 1024 * 1024,
        min_size=128,
        structural_markers=[b"\xFF\xDB", b"\xFF\xC0", b"\xFF\xC4", b"\xFF\xDA"],
        description="JPEG Image (JFIF/EXIF format)"
    ),
    # PNG
    FileSignature(
        format_name="png",
        extensions=["png"],
        magic_bytes=b"\x89PNG\r\n\x1a\n",
        magic_offset=0,
        footer_bytes=b"IEND\xaeB`\x82",
        footer_search_max_distance=40 * 1024 * 1024,
        min_size=64,
        structural_markers=[b"IHDR", b"IDAT", b"IEND"],
        description="Portable Network Graphics"
    ),
    # PDF
    FileSignature(
        format_name="pdf",
        extensions=["pdf"],
        magic_bytes=b"%PDF-",
        magic_offset=0,
        footer_bytes=b"%%EOF",
        footer_search_max_distance=100 * 1024 * 1024,
        min_size=256,
        structural_markers=[b"obj", b"endobj", b"xref", b"trailer"],
        description="Adobe Portable Document Format"
    ),
    # ZIP / DOCX / XLSX
    FileSignature(
        format_name="zip",
        extensions=["zip", "docx", "xlsx"],
        magic_bytes=b"PK\x03\x04",
        magic_offset=0,
        footer_bytes=b"PK\x05\x06",
        footer_search_max_distance=150 * 1024 * 1024,
        min_size=128,
        structural_markers=[b"PK\x01\x02", b"PK\x05\x06"],
        description="ZIP Archive / OpenXML Document"
    ),
    # MP4 (ISO Base Media File Format)
    FileSignature(
        format_name="mp4",
        extensions=["mp4", "m4v", "mov"],
        magic_bytes=b"ftyp",
        magic_offset=4, # bytes 4..7 are 'ftyp'
        footer_bytes=None, # Atom-based chunking
        footer_search_max_distance=500 * 1024 * 1024,
        min_size=512,
        structural_markers=[b"moov", b"mdat", b"free"],
        description="MPEG-4 Part 14 Video"
    ),
    # MP3 (ID3v2 or MPEG sync frame)
    FileSignature(
        format_name="mp3",
        extensions=["mp3"],
        magic_bytes=b"ID3",
        magic_offset=0,
        footer_bytes=None,
        footer_search_max_distance=100 * 1024 * 1024,
        min_size=1024,
        structural_markers=[b"\xFF\xFB", b"\xFF\xF3"],
        description="MPEG Audio Layer III"
    ),
    # SQLite 3 Database
    FileSignature(
        format_name="sqlite",
        extensions=["sqlite", "db", "sqlite3"],
        magic_bytes=b"SQLite format 3\x00",
        magic_offset=0,
        footer_bytes=None,
        footer_search_max_distance=500 * 1024 * 1024,
        min_size=512,
        structural_markers=[],
        description="SQLite Database File"
    ),
]

def find_signature_match(data: bytes, offset_in_data: int = 0) -> List[Tuple[FileSignature, int]]:
    """
    Search data buffer for known signatures.
    Returns list of (signature, relative_offset) tuples.
    """
    matches = []
    data_len = len(data)
    
    for sig in SIGNATURE_DATABASE:
        prefix_len = len(sig.magic_bytes)
        target_offset = sig.magic_offset
        
        # Fast direct check at offset_in_data
        if data_len >= target_offset + prefix_len:
            if data[target_offset:target_offset + prefix_len] == sig.magic_bytes:
                matches.append((sig, 0))
                continue
                
        # Scan search within small header window
        search_window = min(data_len, 4096)
        pos = data.find(sig.magic_bytes, 0, search_window)
        while pos != -1:
            sig_start = pos - sig.magic_offset
            if sig_start >= 0 and (sig, sig_start) not in matches:
                matches.append((sig, sig_start))
            pos = data.find(sig.magic_bytes, pos + 1, search_window)
            
    return matches
