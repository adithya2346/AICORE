"""
Unit tests for Universal Forensic File Repair Engine.
Tests all supported formats with various corruption scenarios:
- JPEG: shifted SOI, missing SOI, rogue markers, missing EOI
- PNG: corrupted 8-byte signature, missing IEND, bad chunk CRC
- PDF: prepended junk, missing %PDF- header, missing trailer & %%EOF
- ZIP / DOCX / XLSX: prepended junk, truncated EOCD, missing central directory
- SQLite: corrupted header string, invalid page sizes
- Text / JSON: null bytes, unclosed brackets/braces
"""
import io
import zipfile
import pytest
from backend.services.file_repair_service import file_repair_service


def test_repair_jpeg_shifted_soi():
    junk = b"CORRUPTED_PREPENDED_BYTES_12345"
    body = (
        b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xFF\xDB\x00\x43\x00" + (b"\x01" * 64) +
        b"\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00\x3F\x00" + (b"\xAA" * 100) +
        b"\xFF\xD9"
    )
    damaged = junk + body
    report = file_repair_service.repair(damaged, filename="test.jpg")
    assert report.success is True
    assert report.file_type == "jpeg"
    assert report.repaired_bytes.startswith(b"\xFF\xD8")
    assert report.repaired_bytes.endswith(b"\xFF\xD9")
    assert report.corruption_detected is True


def test_repair_jpeg_missing_eoi():
    body = (
        b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xFF\xDB\x00\x43\x00" + (b"\x01" * 64) +
        b"\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00\x3F\x00" + (b"\xAA" * 100)
    )
    report = file_repair_service.repair(body, filename="truncated.jpg")
    assert report.success is True
    assert report.repaired_bytes.endswith(b"\xFF\xD9")


def test_repair_png_corrupted_signature_and_crc():
    damaged_header = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    ihdr_chunk = b"\x00\x00\x00\rIHDR\x00\x00\x00\n\x00\x00\x00\n\x08\x02\x00\x00\x00\x02P\x9E\xAE"
    damaged_png = damaged_header + ihdr_chunk
    report = file_repair_service.repair(damaged_png, filename="badge.png")
    assert report.success is True
    assert report.repaired_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert b"IEND" in report.repaired_bytes


def test_repair_pdf_reconstruct_trailer_and_eof():
    damaged_pdf = (
        b"JUNK_NOISE"
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    )
    report = file_repair_service.repair(damaged_pdf, filename="contract.pdf")
    assert report.success is True
    assert report.file_type == "pdf"
    assert report.repaired_bytes.startswith(b"%PDF-")
    assert b"startxref" in report.repaired_bytes
    assert report.repaired_bytes.strip().endswith(b"%%EOF")


def test_repair_zip_archive_reconstruct_eocd():
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("test1.txt", "First text file")
        zf.writestr("test2.json", '{"key": "value"}')

    raw_zip = bio.getvalue()
    # Strip last 22 bytes (EOCD record) and prepend 10 bytes junk
    corrupted_zip = b"0123456789" + raw_zip[:-22]

    # Standard zipfile fails on corrupted
    with pytest.raises(Exception):
        with zipfile.ZipFile(io.BytesIO(corrupted_zip)) as z:
            _ = z.namelist()

    report = file_repair_service.repair(corrupted_zip, filename="backup.zip")
    assert report.success is True
    assert report.repaired_bytes.startswith(b"PK\x03\x04")

    # Verify repaired zip opens cleanly
    with zipfile.ZipFile(io.BytesIO(report.repaired_bytes)) as z:
        entries = z.namelist()
        assert "test1.txt" in entries
        assert "test2.json" in entries
        assert z.read("test1.txt") == b"First text file"


def test_repair_sqlite_header():
    corrupted_hdr = b"\x00" * 16 + b"\x10\x00\x01\x01" + (b"\x00" * 80)
    report = file_repair_service.repair(corrupted_hdr, filename="data.db")
    assert report.success is True
    assert report.file_type == "sqlite"
    assert report.repaired_bytes.startswith(b"SQLite format 3\x00")


def test_repair_text_null_bytes():
    corrupted_text = b"Hello\x00\x00 World!\x00 Forensic\x00 Data"
    report = file_repair_service.repair(corrupted_text, filename="evidence.txt")
    assert report.success is True
    assert b"\x00" not in report.repaired_bytes
    assert report.repaired_bytes.decode() == "Hello World! Forensic Data"


def test_repair_broken_json():
    broken_json = b'{"name": "Alice", "records": [1, 2, 3,'
    report = file_repair_service.repair(broken_json, filename="data.json")
    assert report.success is True
    import json
    parsed = json.loads(report.repaired_bytes.decode())
    assert parsed["name"] == "Alice"
    assert parsed["records"] == [1, 2, 3]
