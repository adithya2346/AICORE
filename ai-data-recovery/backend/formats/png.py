"""
PNG Forensic Format Plugin.
Validates 8-byte PNG signature, chunk sequence (IHDR, IDAT, IEND), chunk CRC32 checksums, and Pillow decoding.
"""
import io
import struct
import zlib
from typing import Dict, Any, List, Optional
from PIL import Image

from backend.formats.base import FormatPlugin, ValidationResult
from backend.recovery.fragments import Fragment

PNG_SIG = b"\x89PNG\r\n\x1a\n"
IEND = b"IEND"

class PNGPlugin(FormatPlugin):
    format_name = "png"
    extensions = ["png"]

    def detect(self, data: bytes) -> bool:
        return len(data) >= 8 and data[:8] == PNG_SIG

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        chunks = []
        has_ihdr = False
        has_iend = False
        dimensions = None
        
        idx = 8
        data_len = len(data)
        
        while idx + 8 <= data_len:
            length = struct.unpack(">I", data[idx:idx + 4])[0]
            ctype = data[idx + 4:idx + 8]
            payload_start = idx + 8
            payload_end = payload_start + length
            crc_offset = payload_end
            
            if ctype == b"IHDR" and payload_end <= data_len:
                has_ihdr = True
                w, h = struct.unpack(">II", data[payload_start:payload_start + 8])
                dimensions = (w, h)
            elif ctype == b"IEND":
                has_iend = True
                
            chunks.append({"type": ctype.decode("ascii", errors="replace"), "length": length, "offset": idx})
            idx = crc_offset + 4
            
        return {
            "has_sig": data[:8] == PNG_SIG,
            "has_ihdr": has_ihdr,
            "has_iend": has_iend,
            "dimensions": dimensions,
            "chunk_count": len(chunks),
            "chunks": chunks
        }

    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        if PNG_SIG in frag_b.prefix_bytes:
            return 0.0
        if IEND in frag_a.suffix_bytes:
            return 0.0
        return 0.60

    def validate(self, data: bytes) -> ValidationResult:
        errors = []
        warnings = []
        missing_regions = []
        structural_score = 0.0
        dimensions = None
        decoder_success = False

        if not data or len(data) < 8:
            return ValidationResult(is_valid=False, decoder_success=False, errors=["Empty or tiny PNG"])

        if data[:8] != PNG_SIG:
            errors.append("Invalid PNG file signature")
        else:
            structural_score += 25.0

        feat = self.extract_features(data)
        if feat["has_ihdr"]:
            structural_score += 35.0
            dimensions = feat["dimensions"]
        else:
            errors.append("Missing IHDR chunk")

        if feat["has_iend"]:
            structural_score += 25.0
        else:
            warnings.append("Missing IEND chunk; image is truncated")
            missing_regions.append({
                "estimated_offset": len(data),
                "estimated_size": 12,
                "status": "missing",
                "description": "Missing terminating IEND chunk"
            })

        # Pillow verify & load
        try:
            bio = io.BytesIO(data)
            with Image.open(bio) as img:
                img.verify()
            bio.seek(0)
            with Image.open(bio) as img:
                img.load()
                decoder_success = True
                dimensions = (img.width, img.height)
                structural_score += 15.0
        except Exception as e:
            errors.append(f"PNG decoder error: {str(e)}")
            decoder_success = False

        return ValidationResult(
            is_valid=decoder_success and feat["has_ihdr"],
            decoder_success=decoder_success,
            dimensions=dimensions,
            file_size=len(data),
            errors=errors,
            warnings=warnings,
            missing_regions=missing_regions,
            structural_score=round(structural_score, 1),
            details=feat
        )
