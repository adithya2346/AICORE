"""
PDF Forensic Format Plugin.
Validates %PDF- header, cross-reference tables (xref), object dictionary balance, trailer, and %%EOF.
"""
from typing import Dict, Any, List, Optional
from backend.formats.base import FormatPlugin, ValidationResult
from backend.recovery.fragments import Fragment

class PDFPlugin(FormatPlugin):
    format_name = "pdf"
    extensions = ["pdf"]

    def detect(self, data: bytes) -> bool:
        return b"%PDF-" in data[:1024]

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        has_header = b"%PDF-" in data[:1024]
        has_eof = b"%%EOF" in data[-1024:]
        has_xref = b"xref" in data
        has_trailer = b"trailer" in data
        obj_count = data.count(b"obj")
        endobj_count = data.count(b"endobj")
        
        return {
            "has_header": has_header,
            "has_eof": has_eof,
            "has_xref": has_xref,
            "has_trailer": has_trailer,
            "obj_count": obj_count,
            "endobj_count": endobj_count
        }

    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        if b"%PDF-" in frag_b.prefix_bytes:
            return 0.0
        if b"%%EOF" in frag_a.suffix_bytes:
            return 0.0
        return 0.55

    def validate(self, data: bytes) -> ValidationResult:
        errors = []
        warnings = []
        missing_regions = []
        score = 0.0

        if not data or len(data) < 32:
            return ValidationResult(is_valid=False, decoder_success=False, errors=["Empty or tiny PDF"])

        feat = self.extract_features(data)
        if feat["has_header"]:
            score += 25.0
        else:
            errors.append("Missing %PDF- header")

        if feat["has_eof"]:
            score += 25.0
        else:
            warnings.append("Missing %%EOF marker; document trailer may be incomplete")
            missing_regions.append({
                "estimated_offset": len(data),
                "estimated_size": 128,
                "status": "missing",
                "description": "Missing %%EOF trailer"
            })

        if feat["has_xref"]:
            score += 25.0
        else:
            warnings.append("Missing cross-reference (xref) table")

        if feat["obj_count"] > 0:
            score += 15.0
            if feat["obj_count"] != feat["endobj_count"]:
                warnings.append(f"Mismatched object markers: {feat['obj_count']} obj vs {feat['endobj_count']} endobj")
            else:
                score += 10.0

        is_valid = feat["has_header"] and (feat["has_eof"] or feat["has_xref"])

        return ValidationResult(
            is_valid=is_valid,
            decoder_success=is_valid,
            file_size=len(data),
            errors=errors,
            warnings=warnings,
            missing_regions=missing_regions,
            structural_score=round(score, 1),
            details=feat
        )
