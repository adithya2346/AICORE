"""
MP3 Forensic Format Plugin.
Validates ID3v2 tags and MPEG audio sync frame headers.
"""
from typing import Dict, Any, List, Optional
from backend.formats.base import FormatPlugin, ValidationResult
from backend.recovery.fragments import Fragment

class MP3Plugin(FormatPlugin):
    format_name = "mp3"
    extensions = ["mp3"]

    def detect(self, data: bytes) -> bool:
        if len(data) >= 3 and data[:3] == b"ID3":
            return True
        if len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
            return True
        return False

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        has_id3 = len(data) >= 3 and data[:3] == b"ID3"
        sync_count = 0
        for i in range(len(data) - 1):
            if data[i] == 0xFF and (data[i + 1] & 0xE0) == 0xE0:
                sync_count += 1
                if sync_count > 50:
                    break
        return {"has_id3": has_id3, "sync_frames_found": sync_count}

    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        if b"ID3" in frag_b.prefix_bytes:
            return 0.0
        return 0.50

    def validate(self, data: bytes) -> ValidationResult:
        if not data or len(data) < 128:
            return ValidationResult(is_valid=False, decoder_success=False, errors=["Empty or tiny MP3"])

        feat = self.extract_features(data)
        is_valid = feat["has_id3"] or (feat["sync_frames_found"] >= 2)
        score = 50.0 if feat["has_id3"] else 20.0
        score += min(50.0, feat["sync_frames_found"] * 2.0)

        return ValidationResult(
            is_valid=is_valid,
            decoder_success=is_valid,
            file_size=len(data),
            errors=[] if is_valid else ["No valid ID3 or MPEG sync frames found"],
            structural_score=round(score, 1),
            details=feat
        )
