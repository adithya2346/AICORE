"""
ZIP Forensic Format Plugin.
Handles ZIP archives, DOCX, and XLSX OpenXML packages.
Validates local file headers, central directories, and end-of-central-directory (EOCD).
"""
import io
import zipfile
from typing import Dict, Any, List, Optional

from backend.formats.base import FormatPlugin, ValidationResult
from backend.recovery.fragments import Fragment

ZIP_LOCAL_HDR = b"PK\x03\x04"
ZIP_EOCD = b"PK\x05\x06"

class ZIPPlugin(FormatPlugin):
    format_name = "zip"
    extensions = ["zip", "docx", "xlsx"]

    def detect(self, data: bytes) -> bool:
        return len(data) >= 4 and data[:4] == ZIP_LOCAL_HDR

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        local_count = data.count(ZIP_LOCAL_HDR)
        has_eocd = ZIP_EOCD in data
        has_docx_manifest = b"[Content_Types].xml" in data
        return {
            "has_header": data[:4] == ZIP_LOCAL_HDR,
            "has_eocd": has_eocd,
            "local_header_count": local_count,
            "is_openxml_doc": has_docx_manifest
        }

    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        if ZIP_LOCAL_HDR in frag_b.prefix_bytes:
            return 0.50
        if ZIP_EOCD in frag_a.suffix_bytes:
            return 0.0
        return 0.60

    def validate(self, data: bytes) -> ValidationResult:
        errors = []
        warnings = []
        missing_regions = []
        score = 0.0
        decoder_success = False
        files_listed = []

        if not data or len(data) < 22:
            return ValidationResult(is_valid=False, decoder_success=False, errors=["Empty or tiny ZIP"])

        if data[:4] == ZIP_LOCAL_HDR:
            score += 25.0
        else:
            errors.append("Missing ZIP local file header signature")

        if ZIP_EOCD in data:
            score += 25.0
        else:
            warnings.append("Missing End of Central Directory record (PK\\x05\\x06); archive is truncated")
            missing_regions.append({
                "estimated_offset": len(data),
                "estimated_size": 22,
                "status": "missing",
                "description": "Missing EOCD record"
            })

        # Test using python's zipfile engine
        try:
            bio = io.BytesIO(data)
            with zipfile.ZipFile(bio, "r") as zf:
                files_listed = zf.namelist()
                bad_file = zf.testzip()
                if bad_file is None:
                    decoder_success = True
                    score += 50.0
                else:
                    errors.append(f"Corrupted entry within ZIP archive: {bad_file}")
                    score += 20.0
        except Exception as e:
            errors.append(f"ZIP unpack error: {str(e)}")

        is_valid = decoder_success and (data[:4] == ZIP_LOCAL_HDR)

        return ValidationResult(
            is_valid=is_valid,
            decoder_success=decoder_success,
            file_size=len(data),
            errors=errors,
            warnings=warnings,
            missing_regions=missing_regions,
            structural_score=round(score, 1),
            details={"entries": files_listed[:20], "entry_count": len(files_listed)}
        )
