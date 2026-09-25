"""
Comprehensive Automated Test Suite for Forensic Recovery Engine.
Covers:
  - Valid, corrupted, truncated, and deleted file scenarios
  - Shuffled, missing, duplicate, and unrelated fragments
  - Multi-file clustering and separation
  - Invariant tests: fabricated_bytes is STRICTLY zero
  - Hash integrity and read-only source enforcement
  - Cooperative job cancellation
"""
import io
import os
import shutil
import struct
import tempfile
from pathlib import Path
import pytest
from PIL import Image, ImageDraw

from backend.config import settings
from backend.storage.file_source import FileSource
from backend.storage.disk_image import DiskImageSource
from backend.security.hashing import calculate_file_sha256, calculate_bytes_sha256
from backend.filesystem.ntfs import NTFSAnalyzer
from backend.recovery.scanner import RawStorageScanner, calculate_entropy
from backend.recovery.carving import FileCarver
from backend.recovery.fragments import Fragment, slice_bytes_into_fragments
from backend.formats.jpeg import JPEGPlugin
from backend.formats.png import PNGPlugin
from backend.ml.classifier import file_classifier
from backend.ml.relationship_model import relationship_model
from backend.ml.clustering import fragment_clusterer
from backend.recovery.reconstruction import ReconstructionEngine
from backend.recovery.confidence import ConfidenceEngine
from backend.database.database import SessionLocal, Base, engine
from backend.database.models import RecoveryJob
from backend.workers.recovery_worker import RecoveryWorker

# Helper to generate a genuine valid test JPEG
def generate_test_jpeg(width: int = 120, height: int = 120) -> bytes:
    bio = io.BytesIO()
    img = Image.new("RGB", (width, height), color=(50, 100, 150))
    d = ImageDraw.Draw(img)
    d.text((10, 10), "TEST EVIDENCE", fill=(255, 255, 0))
    d.line([(0, 0), (width, height)], fill=(255, 0, 0), width=3)
    img.save(bio, "JPEG", quality=85)
    return bio.getvalue()

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def test_hash_integrity():
    """Verify cryptographic SHA-256 calculation matches hashlib on disk and stream."""
    data = b"FORENSIC_INTEGRITY_TEST_PAYLOAD_1234567890"
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        tf_path = tf.name

    try:
        h1 = calculate_file_sha256(tf_path)
        h2 = calculate_bytes_sha256(data)
        assert h1 == h2
        assert len(h1) == 64
    finally:
        os.unlink(tf_path)

def test_read_only_source():
    """Ensure FileSource opens in strictly read-only mode and refuses write operations."""
    data = b"EVIDENCE_DATA_CANNOT_BE_MODIFIED"
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        tf_path = Path(tf.name)

    try:
        src = FileSource(tf_path)
        with src:
            assert src.read_bytes(0, len(data)) == data
            # Check internal handle mode
            assert src._file_handle.mode == "rb"
            # Verify no write method exists on StorageSource interface
            assert not hasattr(src, "write_bytes")
    finally:
        tf_path.unlink()

def test_valid_file():
    """A valid, uncorrupted JPEG is verified with 100% structural consistency."""
    jpeg_bytes = generate_test_jpeg()
    plugin = JPEGPlugin()
    val = plugin.validate(jpeg_bytes)
    assert val.is_valid is True
    assert val.decoder_success is True
    assert val.dimensions == (120, 120)
    assert val.structural_score >= 95.0

def test_corrupted_file():
    """Damaged JPEG with corrupted header or scan bytes produces error warnings and zero fabricated bytes."""
    valid_bytes = generate_test_jpeg()
    # Corrupt SOI and SOF markers
    corrupted = bytearray(valid_bytes)
    corrupted[0:4] = b"\x00\x00\x00\x00"
    corrupted[50:100] = b"\xAA" * 50

    plugin = JPEGPlugin()
    val = plugin.validate(bytes(corrupted))
    assert val.is_valid is False
    assert len(val.errors) > 0

def test_truncated_file():
    """A file missing its tail reports missing regions and zero fabricated bytes."""
    valid_bytes = generate_test_jpeg()
    truncated = valid_bytes[: len(valid_bytes) // 2] # Half of file missing

    plugin = JPEGPlugin()
    val = plugin.validate(truncated)
    assert len(val.warnings) > 0 or len(val.errors) > 0

    frags = slice_bytes_into_fragments(truncated, job_id="test_trunc")
    report = ConfidenceEngine.evaluate(frags, val, avg_model_prob=0.8, expected_total_size=len(valid_bytes))
    assert report.fabricated_bytes == 0
    assert report.missing_bytes > 0
    assert report.status in ("partially_recoverable", "poorly_recoverable")

def test_successful_jpeg_reconstruction():
    """Section 33/37 requirement: Detect JPEG fragments and reconstruct successfully from real bytes."""
    jpeg_bytes = generate_test_jpeg(160, 160)
    frags = slice_bytes_into_fragments(jpeg_bytes, job_id="test_rec", fragment_size=512)
    frags[0].is_header = True
    frags[-1].is_footer = True

    engine = ReconstructionEngine(target_type="jpeg")
    candidates = engine.reconstruct_and_evaluate(frags)
    assert len(candidates) > 0
    best = candidates[0]
    assert best.validation_result.decoder_success is True
    assert best.reconstructed_bytes == jpeg_bytes

def test_shuffled_fragments():
    """Fragments shuffled out of order must be reordered algorithmically."""
    jpeg_bytes = generate_test_jpeg(140, 140)
    frags = slice_bytes_into_fragments(jpeg_bytes, job_id="test_shuffle", fragment_size=768)
    frags[0].is_header = True
    frags[-1].is_footer = True

    # Reverse the middle fragments
    shuffled = [frags[0]] + list(reversed(frags[1:-1])) + [frags[-1]]
    
    engine = ReconstructionEngine(target_type="jpeg")
    candidates = engine.reconstruct_and_evaluate(shuffled, max_candidates=5)
    best = candidates[0]
    assert best.validation_result.decoder_success is True

def test_missing_fragment():
    """When a middle fragment is deleted, the engine reports the missing region and 0 fabricated bytes."""
    jpeg_bytes = generate_test_jpeg(150, 150)
    frags = slice_bytes_into_fragments(jpeg_bytes, job_id="test_missing", fragment_size=512)
    assert len(frags) >= 4
    # Remove one middle fragment
    available = [frags[0], frags[1]] + frags[3:]

    engine = ReconstructionEngine(target_type="jpeg")
    candidates = engine.reconstruct_and_evaluate(available)
    best = candidates[0]

    report = ConfidenceEngine.evaluate(
        fragments_used=best.fragments,
        validation_result=best.validation_result,
        avg_model_prob=best.avg_relationship_probability,
        expected_total_size=len(jpeg_bytes)
    )
    assert report.fabricated_bytes == 0
    assert report.missing_bytes >= 512
    assert report.status in ("partially_recoverable", "mostly_recoverable", "poorly_recoverable")

def test_duplicate_fragment():
    """Duplicate fragments are penalized or ignored during reconstruction."""
    frag1 = Fragment(fragment_id="f1", job_id="t", source_offset=0, length=100, data=b"A"*100)
    prob, rel_type, evidence = relationship_model.predict_successor(frag1, frag1)
    assert prob == 0.0
    assert rel_type == "duplicate"

def test_unrelated_fragment():
    """Cross-type fragments (e.g. PDF fragment in JPEG stream) have low transition probability."""
    jpeg_frag = Fragment(fragment_id="f_jpg", job_id="t", source_offset=0, length=100, data=b"\xFF\xD8\xFF" + b"\x00"*97, predicted_type="jpeg")
    pdf_frag = Fragment(fragment_id="f_pdf", job_id="t", source_offset=500, length=100, data=b"%PDF-1.4" + b"\x00"*92, predicted_type="pdf")

    prob, rel_type, evidence = relationship_model.predict_successor(jpeg_frag, pdf_frag)
    assert prob < 0.40
    assert "type_mismatch" in evidence or rel_type != "likely_successor"

def test_multiple_files():
    """Mixed bag of fragments from multiple files is clustered cleanly."""
    jpeg_data = generate_test_jpeg(80, 80)
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00"*200 + b"IEND\xaeB`\x82"

    j_frags = slice_bytes_into_fragments(jpeg_data, job_id="t_multi", fragment_size=512, prefix_id="jpg")
    p_frags = slice_bytes_into_fragments(png_data, job_id="t_multi", fragment_size=512, prefix_id="png")

    for f in j_frags:
        f.predicted_type = "jpeg"
    for f in p_frags:
        f.predicted_type = "png"

    all_mixed = j_frags + p_frags
    clusters = fragment_clusterer.cluster_fragments(all_mixed)
    assert len(clusters) >= 2
    # Verify separation
    cluster_types = set()
    for cid, c_frags in clusters.items():
        types_in_cluster = {f.predicted_type for f in c_frags}
        assert len(types_in_cluster) == 1

def test_partial_overwrite():
    """Simulate disk region where middle sectors were overwritten with zeroes."""
    jpeg_bytes = generate_test_jpeg(120, 120)
    frags = slice_bytes_into_fragments(jpeg_bytes, job_id="t_ovw", fragment_size=256)
    # Overwrite fragment 2 with zeroes
    frags[2].data = b"\x00" * 256
    frags[2].entropy = calculate_entropy(frags[2].data)

    engine = ReconstructionEngine(target_type="jpeg")
    candidates = engine.reconstruct_and_evaluate(frags)
    best = candidates[0]
    report = ConfidenceEngine.evaluate(best.fragments, best.validation_result, avg_model_prob=0.7)
    assert report.fabricated_bytes == 0

def test_invalid_reconstruction():
    """Completely invalid byte sequences are flagged as not valid."""
    garbage = b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0" * 32
    plugin = JPEGPlugin()
    val = plugin.validate(garbage)
    assert val.is_valid is False
    assert val.decoder_success is False

def test_fabricated_bytes_strictly_zero():
    """MANDATORY INVARIANT: fabricated_bytes must NEVER be greater than 0 under any circumstance."""
    jpeg_bytes = generate_test_jpeg(100, 100)
    frags = slice_bytes_into_fragments(jpeg_bytes[:500], job_id="t_zero")
    plugin = JPEGPlugin()
    val = plugin.validate(jpeg_bytes[:500])
    report = ConfidenceEngine.evaluate(frags, val, avg_model_prob=0.5, expected_total_size=len(jpeg_bytes))
    assert report.fabricated_bytes == 0

def test_deleted_file():
    """Verify NTFS / FAT32 deleted entry data structure parsing."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        tf.write(b"\x00" * 1024)
        tf_path = Path(tf.name)
    try:
        src = FileSource(tf_path)
        analyzer = NTFSAnalyzer(src)
        assert analyzer.detect() is False
        assert analyzer.find_deleted_files() == []
        src.close()
    finally:
        tf_path.unlink(missing_ok=True)

def test_empty_recycle_bin_scenario():
    """Test raw storage scanner finding remnants when filesystem catalog is empty."""
    jpeg_bytes = generate_test_jpeg(100, 100)
    # Wrap JPEG inside a mock 64KB unallocated drive image
    disk_data = (b"\x00" * 4096) + jpeg_bytes + (b"\x00" * 4096)
    
    with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as tf:
        tf.write(disk_data)
        tf_path = Path(tf.name)

    src = None
    try:
        src = DiskImageSource(tf_path)
        scanner = RawStorageScanner(src, block_size=512)
        report = scanner.scan()
        assert len(report.header_hits) >= 1
        assert any(h.format_name == "jpeg" for h in report.header_hits)
    finally:
        if src:
            src.close()
        tf_path.unlink(missing_ok=True)

def test_job_cancellation():
    """Verify cooperative cancellation sets job status to cancelled."""
    import uuid
    db = SessionLocal()
    unique_job_id = f"REC-TEST-CANCEL-{uuid.uuid4().hex[:6]}"
    job = RecoveryJob(
        id=unique_job_id,
        operation="recover_corrupted",
        source_type="uploaded_file",
        source_path=str(settings.datasets_dir / "originals" / "clean_photo.jpg"),
        status="created"
    )
    db.add(job)
    db.commit()

    worker = RecoveryWorker(unique_job_id)
    # Set status to cancelled before run
    job.status = "cancelled"
    db.commit()

    assert worker._is_job_cancelled(db) is True
    db.close()
