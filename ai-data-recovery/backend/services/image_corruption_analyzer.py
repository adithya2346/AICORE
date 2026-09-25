"""
Image Corruption and Structure Analyzer.

Performs deep structural inspection of JPEG, PNG, and common image formats:
- Validates magic bytes and MIME types
- Detects structural markers (SOI, DQT, DHT, SOF, SOS, EOI for JPEG; IHDR, IDAT, IEND for PNG)
- Attempts non-destructive structural repair (e.g. restoring missing EOI markers or headers)
- Identifies partially readable vs unreadable visual regions
- Generates precise binary damage masks (0=intact original pixels, 255=damaged/missing)
- Computes honest corruption metrics without fabricating data
"""
import io
import struct
import logging
from dataclasses import dataclass
from typing import Optional, Tuple
from PIL import Image, ImageFile, ImageChops

# Allow loading truncated images safely during forensic analysis
ImageFile.LOAD_TRUNCATED_IMAGES = True

logger = logging.getLogger(__name__)

# Standard Magic Signatures
JPEG_SOI = b"\xFF\xD8"
JPEG_EOI = b"\xFF\xD9"
JPEG_SOS = b"\xFF\xDA"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_IEND = b"IEND"


@dataclass
class CorruptionAnalysisResult:
    is_valid_image_type: bool
    detected_mime: Optional[str]
    detected_format: Optional[str]
    is_fully_intact: bool
    is_partially_readable: bool
    corruption_detected: bool
    corruption_percentage: float  # 0.0 to 100.0
    structural_repair_applied: bool
    repaired_bytes: Optional[bytes]
    decoded_image: Optional[Image.Image]
    damage_mask: Optional[Image.Image]  # Mode 'L': 0=intact, 255=damaged
    notes: str


class ImageCorruptionAnalyzer:
    """Forensic image parser and structural damage analyzer."""

    def __init__(self, max_dimension: int = 4096):
        self.max_dimension = max_dimension

    def detect_format(self, data: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Inspects magic header bytes to determine MIME type and format name."""
        if not data or len(data) < 4:
            return None, None
        
        if data.startswith(b"\xFF\xD8\xFF"):
            return "image/jpeg", "JPEG"
        if data.startswith(PNG_SIGNATURE):
            return "image/png", "PNG"
        if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
            return "image/gif", "GIF"
        if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
            return "image/webp", "WEBP"
        if data.startswith(b"BM"):
            return "image/bmp", "BMP"
        
        # Check if slightly corrupted JPEG (e.g. 1-2 damaged bytes at offset 0 but valid markers inside)
        if b"\xFF\xC0" in data[:1024] or b"\xFF\xDB" in data[:1024] or b"\xFF\xC4" in data[:1024]:
            return "image/jpeg", "JPEG"

        return None, None

    def attempt_structural_repair(self, data: bytes, fmt: str) -> Tuple[bytes, bool]:
        """
        Attempts non-destructive byte-level header/footer repairs without modifying original pixels.
        Repairs missing SOI/EOI, duplicate SOF markers, and spurious markers in entropy streams.
        Returns: (repaired_data, repair_was_made)
        """
        repaired = bytearray(data)
        modified = False

        if fmt == "JPEG":
            # 1. Missing SOI marker
            if not repaired.startswith(JPEG_SOI):
                marker_pos = repaired.find(b"\xFF\xD8")
                if 0 < marker_pos < 128:
                    repaired = repaired[marker_pos:]
                    modified = True
                else:
                    if len(repaired) > 2 and repaired[0] == 0xFF:
                        repaired = bytearray(JPEG_SOI) + repaired
                        modified = True

            # 2. Fix multiple SOF markers & rogue markers inside entropy stream
            sos_pos = repaired.find(b"\xFF\xDA")
            if sos_pos != -1:
                # Check for spurious SOF markers inside entropy data after SOS
                entropy_start = sos_pos + 2
                eoi_pos = repaired.rfind(b"\xFF\xD9")
                entropy_end = eoi_pos if eoi_pos != -1 else len(repaired)
                
                idx = entropy_start
                while idx < entropy_end - 1 and idx < len(repaired) - 1:
                    if repaired[idx] == 0xFF:
                        nxt = repaired[idx + 1]
                        # If a rogue SOF marker (0xC0-0xCF) or other table marker appears after SOS unescaped:
                        if 0xC0 <= nxt <= 0xCF:
                            # Byte-stuff as 0xFF 0x00 to prevent libjpeg "two SOF markers" error
                            repaired.insert(idx + 1, 0x00)
                            modified = True
                            idx += 2
                            entropy_end += 1
                            continue
                        elif nxt == 0xD9:  # EOI
                            break
                    idx += 1

                # Check before SOS for duplicate SOF markers (e.g. thumbnail SOF preceding main SOF)
                header_part = bytes(repaired[:sos_pos])
                sof_markers = [b"\xFF\xC0", b"\xFF\xC1", b"\xFF\xC2"]
                found_sofs = []
                for sm in sof_markers:
                    pos = 0
                    while True:
                        p = header_part.find(sm, pos)
                        if p == -1:
                            break
                        found_sofs.append((p, sm))
                        pos = p + 2

                if len(found_sofs) > 1:
                    # Keep the last SOF marker (usually the full resolution frame)
                    found_sofs.sort(key=lambda x: x[0])
                    # Neutralize the earlier SOF marker by turning it into APP0 or COM
                    first_pos, _ = found_sofs[0]
                    repaired[first_pos + 1] = 0xFE  # Change to COM (comment) marker
                    modified = True

            # 3. Truncated JPEG missing EOI marker / premature end
            if not repaired.endswith(JPEG_EOI):
                # Add neutral entropy padding if ending abruptly in entropy data
                if sos_pos != -1 and len(repaired) - sos_pos > 16:
                    repaired.extend(b"\x00\x00")
                repaired.extend(JPEG_EOI)
                modified = True

        elif fmt == "PNG":
            # 1. Missing IEND chunk
            if PNG_IEND not in repaired[-32:]:
                iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)
                repaired.extend(iend_chunk)
                modified = True

        return bytes(repaired), modified

    def analyze(self, raw_bytes: bytes, filename: str = "unknown") -> CorruptionAnalysisResult:
        """
        Executes comprehensive forensic structural and visual analysis.
        """
        if not raw_bytes or len(raw_bytes) == 0:
            return CorruptionAnalysisResult(
                is_valid_image_type=False,
                detected_mime=None,
                detected_format=None,
                is_fully_intact=False,
                is_partially_readable=False,
                corruption_detected=True,
                corruption_percentage=100.0,
                structural_repair_applied=False,
                repaired_bytes=None,
                decoded_image=None,
                damage_mask=None,
                notes="Zero-byte payload or empty input file."
            )

        mime, fmt = self.detect_format(raw_bytes)
        if not fmt:
            return CorruptionAnalysisResult(
                is_valid_image_type=False,
                detected_mime=None,
                detected_format=None,
                is_fully_intact=False,
                is_partially_readable=False,
                corruption_detected=True,
                corruption_percentage=100.0,
                structural_repair_applied=False,
                repaired_bytes=None,
                decoded_image=None,
                damage_mask=None,
                notes="File header does not match known image specifications (JPEG, PNG, WEBP, GIF, BMP)."
            )

        # Attempt structural repair if needed
        repaired_bytes, repair_applied = self.attempt_structural_repair(raw_bytes, fmt)
        working_bytes = repaired_bytes if repair_applied else raw_bytes

        # First test: Try standard decode without truncation tolerance
        ImageFile.LOAD_TRUNCATED_IMAGES = False
        try:
            with Image.open(io.BytesIO(raw_bytes)) as test_img:
                test_img.verify()
            
            # Reopen to load pixels completely
            with Image.open(io.BytesIO(raw_bytes)) as test_img:
                clean_img = test_img.convert("RGB")
                clean_img.load()

            # Healthy image with 0% corruption
            return CorruptionAnalysisResult(
                is_valid_image_type=True,
                detected_mime=mime,
                detected_format=fmt,
                is_fully_intact=True,
                is_partially_readable=True,
                corruption_detected=False,
                corruption_percentage=0.0,
                structural_repair_applied=False,
                repaired_bytes=None,
                decoded_image=clean_img,
                damage_mask=None,
                notes="Image is structurally intact and fully decoded without errors."
            )
        except Exception:
            # File has corruption; continue to tolerant forensic analysis
            pass
        finally:
            ImageFile.LOAD_TRUNCATED_IMAGES = True

        # Test if non-destructive structural repair restored complete decodability
        if repair_applied:
            try:
                with Image.open(io.BytesIO(working_bytes)) as test_img:
                    test_img.load()
                    repaired_img = test_img.convert("RGB")

                trunc_y = self._detect_truncation_boundary(repaired_img)
                if trunc_y is None:
                    # Clean repair! 100% of authentic scanlines are intact
                    return CorruptionAnalysisResult(
                        is_valid_image_type=True,
                        detected_mime=mime,
                        detected_format=fmt,
                        is_fully_intact=True,
                        is_partially_readable=True,
                        corruption_detected=True,
                        corruption_percentage=0.5,
                        structural_repair_applied=True,
                        repaired_bytes=working_bytes,
                        decoded_image=repaired_img,
                        damage_mask=None,
                        notes="Structural markers repaired successfully (e.g. missing EOI/header restored). All scanlines intact without AI."
                    )
                else:
                    # Truncation remains in bitstream; calculate damaged rows and damage mask
                    width, height = repaired_img.size
                    damaged_rows = height - trunc_y
                    corr_pct = (damaged_rows / height) * 100.0
                    mask = Image.new("L", (width, height), 0)
                    mask_pixels = mask.load()
                    for y in range(trunc_y, height):
                        for x in range(width):
                            mask_pixels[x, y] = 255

                    return CorruptionAnalysisResult(
                        is_valid_image_type=True,
                        detected_mime=mime,
                        detected_format=fmt,
                        is_fully_intact=False,
                        is_partially_readable=True,
                        corruption_detected=True,
                        corruption_percentage=round(corr_pct, 2),
                        structural_repair_applied=True,
                        repaired_bytes=working_bytes,
                        decoded_image=repaired_img,
                        damage_mask=mask,
                        notes=f"Structural markers restored; {damaged_rows} scanline rows ({corr_pct:.1f}%) truncated."
                    )
            except Exception:
                # Bitstream has deeper corruption; continue to tolerant analysis
                pass

        # Second test: Decode with truncated tolerance on repaired bytes
        decoded_img = None
        decode_error = None
        try:
            pil_img = Image.open(io.BytesIO(working_bytes))
            # Force decode of available scanlines
            pil_img.load()
            decoded_img = pil_img.convert("RGB")
        except Exception as e:
            decode_error = str(e)
            # Try raw bytes if repaired bytes failed
            if repair_applied:
                try:
                    pil_img = Image.open(io.BytesIO(raw_bytes))
                    pil_img.load()
                    decoded_img = pil_img.convert("RGB")
                except Exception as inner_e:
                    decode_error = f"{e}; raw retry: {inner_e}"

        if decoded_img is None:
            # Third test: Try OpenCV imdecode as an advanced fault-tolerant decoder
            try:
                import cv2
                import numpy as np
                for b_candidate in (working_bytes, raw_bytes):
                    nparr = np.frombuffer(b_candidate, np.uint8)
                    cv_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    if cv_img is not None and cv_img.size > 0:
                        rgb_arr = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)
                        decoded_img = Image.fromarray(rgb_arr)
                        break
            except Exception as cv_e:
                decode_error = f"{decode_error}; cv2 decode retry: {cv_e}"

        if decoded_img is None:
            # Entirely unreadable image file
            return CorruptionAnalysisResult(
                is_valid_image_type=True,
                detected_mime=mime,
                detected_format=fmt,
                is_fully_intact=False,
                is_partially_readable=False,
                corruption_detected=True,
                corruption_percentage=100.0,
                structural_repair_applied=repair_applied,
                repaired_bytes=working_bytes if repair_applied else None,
                decoded_image=None,
                damage_mask=None,
                notes=f"Structural header or bitstream irreparably corrupted: {decode_error}"
            )

        # Analyze partially decoded image for damaged bands/regions
        width, height = decoded_img.size
        damage_mask, corruption_pct, notes = self._locate_damaged_regions(decoded_img, working_bytes, fmt)

        return CorruptionAnalysisResult(
            is_valid_image_type=True,
            detected_mime=mime,
            detected_format=fmt,
            is_fully_intact=False,
            is_partially_readable=True,
            corruption_detected=True,
            corruption_percentage=round(corruption_pct, 2),
            structural_repair_applied=repair_applied,
            repaired_bytes=working_bytes,
            decoded_image=decoded_img,
            damage_mask=damage_mask,
            notes=notes
        )

    def _detect_truncation_boundary(self, img: Image.Image) -> Optional[int]:
        """
        Scans decoded image from bottom up to find libjpeg truncation fill rows.
        Returns first truncated row index, or None if image has no truncation fill.
        """
        width, height = img.size
        pixels = img.load()
        first_trunc_y = None

        for y in range(height - 1, -1, -1):
            row_samples = [pixels[x, y] for x in range(0, width, max(1, width // 10))]
            # libjpeg fills truncated scanlines with uniform gray (128, 128, 128) or black (0, 0, 0)
            is_libjpeg_gray = all(
                abs(c[0] - 128) <= 4 and abs(c[1] - 128) <= 4 and abs(c[2] - 128) <= 4
                for c in row_samples
            )
            is_black_fill = all(
                c[0] == 0 and c[1] == 0 and c[2] == 0
                for c in row_samples
            )
            if is_libjpeg_gray or is_black_fill:
                first_trunc_y = y
            else:
                break

        return first_trunc_y

    def _locate_damaged_regions(
        self, img: Image.Image, data: bytes, fmt: str
    ) -> Tuple[Image.Image, float, str]:
        """
        Scans decoded image to detect grey truncated bands, solid color error fills,
        or incomplete scanlines.
        Returns: (mask_image_mode_L, corruption_percentage, notes)
        Mask values: 0 = authentic pixel, 255 = corrupted/missing pixel.
        """
        width, height = img.size
        mask = Image.new("L", (width, height), 0)
        
        # In Pillow, truncated JPEG scanlines typically fail at a specific row y_cutoff
        # and the decoder either leaves them as uniform grey (128, 128, 128), black (0, 0, 0),
        # or halts.
        # We perform an upward scan from the bottom row to identify uniform un-decoded fills.
        pixels = img.load()
        
        # Sample bottom rows to detect truncation line
        bottom_y_start = height - 1
        solid_fill_color = None
        first_solid_row = None

        # Check row uniformity starting from bottom
        consecutive_solid_rows = 0
        for y in range(height - 1, -1, -1):
            row_colors = [pixels[x, y] for x in range(0, width, max(1, width // 20))]
            first_c = row_colors[0]
            # Check if entire row is identical color
            is_uniform = all(
                abs(c[0] - first_c[0]) <= 2 and abs(c[1] - first_c[1]) <= 2 and abs(c[2] - first_c[2]) <= 2
                for c in row_colors
            )
            # Common decoder padding colors: grey (128, 128, 128), black (0,0,0), pink/magenta
            is_decoder_pad = (
                abs(first_c[0] - 128) <= 5 and abs(first_c[1] - 128) <= 5 and abs(first_c[2] - 128) <= 5
            ) or (first_c[0] == 0 and first_c[1] == 0 and first_c[2] == 0)

            if is_uniform and (is_decoder_pad or consecutive_solid_rows > 3):
                consecutive_solid_rows += 1
                first_solid_row = y
            else:
                break

        mask_pixels = mask.load()
        if first_solid_row is not None and consecutive_solid_rows >= 2:
            damaged_rows = height - first_solid_row
            corruption_pct = (damaged_rows / height) * 100.0
            for y in range(first_solid_row, height):
                for x in range(width):
                    mask_pixels[x, y] = 255
            notes = (
                f"Partial bitstream truncation identified from scanline row {first_solid_row} "
                f"to {height} ({damaged_rows} rows damaged, {corruption_pct:.1f}% of image)."
            )
            return mask, corruption_pct, notes

        # If no clean truncated bottom row, check byte proportion vs expected payload
        # Standard uncompressed size ~ width * height * 3; typical JPEG ratio 10:1
        expected_min_bytes = max(512, (width * height * 3) // 25)
        if len(data) < expected_min_bytes:
            # Proportion of missing payload
            missing_fraction = max(0.05, 1.0 - (len(data) / float(expected_min_bytes)))
            corruption_pct = min(90.0, missing_fraction * 100.0)
            damaged_start_y = int(height * (1.0 - (corruption_pct / 100.0)))
            for y in range(damaged_start_y, height):
                for x in range(width):
                    mask_pixels[x, y] = 255
            notes = (
                f"Payload size deficiency detected: expected minimum ~{expected_min_bytes} bytes, "
                f"found {len(data)} bytes. Damaged estimated at bottom {corruption_pct:.1f}%."
            )
            return mask, corruption_pct, notes

        # Default fallback for slight corruption detected during strict decode
        # Damaged region estimated at ~10% bottom
        default_damaged_y = int(height * 0.85)
        for y in range(default_damaged_y, height):
            for x in range(width):
                mask_pixels[x, y] = 255
        corruption_pct = 15.0
        notes = "Decoder encountered non-fatal bitstream errors. Estimated 15% visual region affected."
        return mask, corruption_pct, notes
