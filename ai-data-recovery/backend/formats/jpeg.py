"""
JPEG Forensic Format Plugin.
Performs marker parsing (SOI, APPn, DQT, DHT, SOF0/2, SOS, EOI), entropy-coded scan analysis,
boundary validation, byte-stuffing checks, and Pillow decoder verification.
"""
import io
import struct
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image

from backend.formats.base import FormatPlugin, ValidationResult
from backend.recovery.fragments import Fragment

# JPEG Markers
SOI = b"\xFF\xD8"
EOI = b"\xFF\xD9"
SOS = b"\xFF\xDA"
DQT = b"\xFF\xDB"
DHT = b"\xFF\xC4"
SOF0 = b"\xFF\xC0"
SOF2 = b"\xFF\xC2"
DRI = b"\xFF\xDD"

class JPEGPlugin(FormatPlugin):
    format_name = "jpeg"
    extensions = ["jpg", "jpeg"]

    def detect(self, data: bytes) -> bool:
        if len(data) >= 3 and data[:3] == b"\xFF\xD8\xFF":
            return True
        return False

    def parse_markers(self, data: bytes) -> Dict[str, Any]:
        """
        Walk JPEG markers to verify structural integrity.
        """
        markers = []
        info: Dict[str, Any] = {
            "has_soi": False,
            "has_eoi": False,
            "has_sof": False,
            "has_sos": False,
            "dqt_count": 0,
            "dht_count": 0,
            "sof_marker": None,
            "dimensions": None,
            "components": None,
            "sos_offset": None,
            "eoi_offset": None,
            "scan_data_length": 0
        }
        
        if not data or len(data) < 4:
            return info
            
        if data[:2] == SOI:
            info["has_soi"] = True
            markers.append({"marker": "SOI", "offset": 0})
            
        idx = 2
        data_len = len(data)
        
        while idx < data_len:
            # Find 0xFF marker prefix
            if data[idx] != 0xFF:
                # Scan data or out-of-sync
                idx += 1
                continue
                
            # Skip any duplicate 0xFF bytes
            while idx < data_len and data[idx] == 0xFF:
                idx += 1
            if idx >= data_len:
                break
                
            marker_code = data[idx]
            idx += 1
            
            # RST markers (0xD0 - 0xD7) and SOI/EOI have no length
            if 0xD0 <= marker_code <= 0xD7:
                markers.append({"marker": f"RST{marker_code - 0xD0}", "offset": idx - 2})
                continue
            if marker_code == 0xD8: # SOI
                continue
            if marker_code == 0xD9: # EOI
                info["has_eoi"] = True
                info["eoi_offset"] = idx - 2
                markers.append({"marker": "EOI", "offset": idx - 2})
                break
            if marker_code == 0x00: # Byte stuffing in entropy data
                continue
                
            # Markers with 16-bit length
            if idx + 2 > data_len:
                break
            marker_len = struct.unpack(">H", data[idx:idx + 2])[0]
            marker_payload_end = idx + marker_len
            
            if marker_code == 0xDB: # DQT
                info["dqt_count"] += 1
                markers.append({"marker": "DQT", "offset": idx - 2, "len": marker_len})
            elif marker_code == 0xC4: # DHT
                info["dht_count"] += 1
                markers.append({"marker": "DHT", "offset": idx - 2, "len": marker_len})
            elif marker_code in (0xC0, 0xC1, 0xC2): # SOF
                info["has_sof"] = True
                info["sof_marker"] = f"SOF{marker_code - 0xC0}"
                if idx + 8 <= data_len:
                    precision = data[idx + 2]
                    height = struct.unpack(">H", data[idx + 3:idx + 5])[0]
                    width = struct.unpack(">H", data[idx + 5:idx + 7])[0]
                    num_comp = data[idx + 7]
                    info["dimensions"] = (width, height)
                    info["components"] = num_comp
                markers.append({"marker": info["sof_marker"], "offset": idx - 2, "len": marker_len})
            elif marker_code == 0xDA: # SOS
                info["has_sos"] = True
                info["sos_offset"] = idx - 2
                markers.append({"marker": "SOS", "offset": idx - 2, "len": marker_len})
                # After SOS payload, entropy-coded scan data begins until EOI
                idx = marker_payload_end
                scan_start = idx
                eoi_pos = data.find(EOI, scan_start)
                if eoi_pos != -1:
                    info["has_eoi"] = True
                    info["eoi_offset"] = eoi_pos
                    info["scan_data_length"] = eoi_pos - scan_start
                    markers.append({"marker": "EOI", "offset": eoi_pos})
                    break
                else:
                    info["scan_data_length"] = data_len - scan_start
                    break
            elif 0xE0 <= marker_code <= 0xEF: # APPn
                markers.append({"marker": f"APP{marker_code - 0xE0}", "offset": idx - 2, "len": marker_len})
            else:
                markers.append({"marker": f"0x{marker_code:02X}", "offset": idx - 2, "len": marker_len})
                
            idx = marker_payload_end
            
        info["markers"] = markers
        return info

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        return self.parse_markers(data)

    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        """
        Validate transition between Fragment A and Fragment B in a JPEG stream.
        """
        score = 0.50
        tail_a = frag_a.suffix_bytes
        head_b = frag_b.prefix_bytes

        # If Frag A is marked as containing EOI, nothing can succeed it
        if EOI in tail_a:
            return 0.0

        # If Frag B has SOI, it cannot succeed anything
        if SOI in head_b:
            return 0.0

        # Byte stuffing check across boundary: 0xFF followed by 0x00 or RST
        if tail_a and tail_a[-1] == 0xFF:
            if head_b:
                next_byte = head_b[0]
                if next_byte == 0x00:
                    score += 0.35 # Valid JPEG escaped 0xFF byte
                elif 0xD0 <= next_byte <= 0xD7:
                    score += 0.30 # Valid restart marker
                elif next_byte == 0xD9:
                    score += 0.30 # EOI marker
                else:
                    return 0.01 # Illegal byte following 0xFF in JPEG scan data

        # Check entropy continuity: JPEG entropy-coded scan data is consistently high
        if frag_a.entropy > 7.0 and frag_b.entropy > 7.0:
            score += 0.15

        return max(0.01, min(0.99, score))

    def validate(self, data: bytes) -> ValidationResult:
        """
        Validate JPEG bytes:
        1. Structural marker walk
        2. Pillow Image.open(), verify(), load() decoding
        3. Missing regions / corruption detection
        """
        errors = []
        warnings = []
        missing_regions = []
        structural_score = 0.0
        dimensions = None
        decoder_success = False

        if not data:
            return ValidationResult(
                is_valid=False,
                decoder_success=False,
                errors=["Empty byte stream"],
                structural_score=0.0
            )

        # 1. Structural marker checks
        meta = self.parse_markers(data)
        
        if not meta["has_soi"]:
            errors.append("Missing JPEG Start of Image (SOI 0xFFD8) marker")
        else:
            structural_score += 20.0
            
        if not meta["has_sof"]:
            errors.append("Missing Start of Frame (SOF) marker; image dimensions unknown")
        else:
            structural_score += 25.0
            dimensions = meta["dimensions"]
            
        if not meta["has_sos"]:
            errors.append("Missing Start of Scan (SOS) marker")
        else:
            structural_score += 25.0
            
        if not meta["has_eoi"]:
            warnings.append("Missing End of Image (EOI 0xFFD9) marker; file may be truncated")
            missing_regions.append({
                "estimated_offset": len(data),
                "estimated_size": 2,
                "status": "missing",
                "description": "Truncated stream missing EOI marker"
            })
        else:
            structural_score += 20.0

        if meta["dqt_count"] > 0:
            structural_score += 5.0
        if meta["dht_count"] > 0:
            structural_score += 5.0

        # 2. Pillow decoder validation
        try:
            bio = io.BytesIO(data)
            with Image.open(bio) as img:
                img.verify() # First pass structural verification
                
            # Second pass: actually decode pixels to catch truncated/corrupted Huffman data
            bio.seek(0)
            with Image.open(bio) as img:
                img.load() # Forces decoder to decode entire entropy stream
                dimensions = (img.width, img.height)
                decoder_success = True
        except Exception as e:
            err_msg = str(e)
            if "image file is truncated" in err_msg.lower():
                warnings.append(f"Decoder warning: {err_msg}")
                # Partial decode might still have worked
                decoder_success = (dimensions is not None)
                missing_regions.append({
                    "estimated_offset": max(0, len(data) - 1024),
                    "estimated_size": 1024,
                    "status": "corrupted_or_truncated",
                    "description": "Incomplete scan data detected by image decoder"
                })
            else:
                errors.append(f"Decoder error: {err_msg}")
                decoder_success = False

        is_valid = (meta["has_soi"] and meta["has_sof"] and meta["has_sos"] and decoder_success)

        return ValidationResult(
            is_valid=is_valid,
            decoder_success=decoder_success,
            dimensions=dimensions,
            file_size=len(data),
            errors=errors,
            warnings=warnings,
            missing_regions=missing_regions,
            structural_score=round(structural_score, 1),
            details=meta
        )
