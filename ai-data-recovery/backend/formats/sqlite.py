"""
SQLite 3 Forensic Format Plugin.
Validates SQLite database header, page size, schema integrity, and sqlite3 query compatibility.
"""
import io
import os
import sqlite3
import struct
import tempfile
from typing import Dict, Any, List, Optional
from backend.formats.base import FormatPlugin, ValidationResult
from backend.recovery.fragments import Fragment

SQLITE_HDR = b"SQLite format 3\x00"

class SQLitePlugin(FormatPlugin):
    format_name = "sqlite"
    extensions = ["sqlite", "db", "sqlite3"]

    def detect(self, data: bytes) -> bool:
        return len(data) >= 16 and data[:16] == SQLITE_HDR

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        if len(data) < 100:
            return {"has_header": False}
        page_size = struct.unpack(">H", data[16:18])[0]
        if page_size == 1:
            page_size = 65536
        freelist_pages = struct.unpack(">I", data[36:40])[0]
        return {
            "has_header": data[:16] == SQLITE_HDR,
            "page_size": page_size,
            "freelist_pages": freelist_pages
        }

    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        if SQLITE_HDR in frag_b.prefix_bytes:
            return 0.0
        return 0.60

    def validate(self, data: bytes) -> ValidationResult:
        errors = []
        warnings = []
        missing_regions = []
        score = 0.0
        decoder_success = False
        tables = []

        if len(data) < 100 or data[:16] != SQLITE_HDR:
            return ValidationResult(is_valid=False, decoder_success=False, errors=["Missing SQLite header string"])

        score += 40.0
        feat = self.extract_features(data)

        # Test against sqlite3 engine via temporary file
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                tf.write(data)
                temp_path = tf.name

            con = sqlite3.connect(temp_path)
            cur = con.cursor()
            cur.execute("PRAGMA quick_check;")
            check_res = cur.fetchall()
            
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cur.fetchall()]
            con.close()

            if check_res and check_res[0][0] == "ok":
                decoder_success = True
                score += 60.0
            else:
                warnings.append(f"SQLite PRAGMA check: {check_res}")
                decoder_success = (len(tables) > 0)
                score += 30.0
        except Exception as e:
            errors.append(f"SQLite engine error: {str(e)}")
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

        is_valid = decoder_success or (feat.get("page_size", 0) in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536))

        return ValidationResult(
            is_valid=is_valid,
            decoder_success=decoder_success,
            file_size=len(data),
            errors=errors,
            warnings=warnings,
            missing_regions=missing_regions,
            structural_score=round(score, 1),
            details={"tables": tables, "features": feat}
        )
