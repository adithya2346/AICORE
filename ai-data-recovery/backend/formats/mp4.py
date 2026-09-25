"""
MP4 Forensic Format Plugin.
Parses ISO BMFF atoms/boxes (ftyp, moov, mdat) to validate video stream structure.
"""
import struct
from typing import Dict, Any, List, Optional
from backend.formats.base import FormatPlugin, ValidationResult
from backend.recovery.fragments import Fragment

class MP4Plugin(FormatPlugin):
    format_name = "mp4"
    extensions = ["mp4", "m4v", "mov"]

    def detect(self, data: bytes) -> bool:
        return len(data) >= 8 and data[4:8] == b"ftyp"

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        atoms = []
        idx = 0
        data_len = len(data)
        has_ftyp = False
        has_moov = False
        has_mdat = False

        while idx + 8 <= data_len:
            size = struct.unpack(">I", data[idx:idx + 4])[0]
            name = data[idx + 4:idx + 8]
            if name == b"ftyp":
                has_ftyp = True
            elif name == b"moov":
                has_moov = True
            elif name == b"mdat":
                has_mdat = True

            atoms.append({"name": name.decode("ascii", errors="replace"), "size": size, "offset": idx})
            if size == 0:
                break
            if size == 1:
                # 64-bit extended size
                if idx + 16 > data_len:
                    break
                size = struct.unpack(">Q", data[idx + 8:idx + 16])[0]
            if size < 8:
                break
            idx += size

        return {
            "has_ftyp": has_ftyp,
            "has_moov": has_moov,
            "has_mdat": has_mdat,
            "atom_count": len(atoms),
            "atoms": atoms[:15]
        }

    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        if b"ftyp" in frag_b.prefix_bytes:
            return 0.0
        return 0.60

    def validate(self, data: bytes) -> ValidationResult:
        errors = []
        warnings = []
        missing_regions = []
        score = 0.0

        if len(data) < 8 or data[4:8] != b"ftyp":
            return ValidationResult(is_valid=False, decoder_success=False, errors=["Missing MP4 ftyp atom"])

        score += 30.0
        feat = self.extract_features(data)

        if feat["has_moov"]:
            score += 40.0
        else:
            warnings.append("Missing moov atom (metadata table); video playback requires moov atom")
            missing_regions.append({
                "estimated_offset": len(data),
                "estimated_size": 4096,
                "status": "missing",
                "description": "Missing moov container atom"
            })

        if feat["has_mdat"]:
            score += 30.0
        else:
            warnings.append("Missing mdat atom (media stream payload)")

        is_valid = feat["has_ftyp"] and (feat["has_moov"] or feat["has_mdat"])

        return ValidationResult(
            is_valid=is_valid,
            decoder_success=feat["has_moov"] and feat["has_mdat"],
            file_size=len(data),
            errors=errors,
            warnings=warnings,
            missing_regions=missing_regions,
            structural_score=round(score, 1),
            details=feat
        )
