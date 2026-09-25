"""
Comprehensive Automated Test Suite for AI-Assisted Image Recovery Module.

Covers all mandatory test scenarios:
1. Healthy JPEG -> no AI call.
2. Slightly corrupted JPEG -> structural recovery.
3. Partially corrupted JPEG -> fragment recovery + AI restoration.
4. Completely invalid file -> reject.
5. AI API unavailable -> normal recovery still works.
6. Missing API key -> clear configuration error.
7. Large file -> proper size validation.
8. Original file remains unchanged (immutability).

Includes automated test mode recording:
- input hash
- output hash
- file sizes
- recovery method
- corruption level
- AI API status
- validation result
"""
import io
import os
import hashlib
import tempfile
from pathlib import Path
import pytest
from PIL import Image, ImageDraw

from backend.config import settings
from backend.services.ai_recovery_service import AIRecoveryService
from backend.services.providers.factory import get_ai_provider
from backend.services.providers.base import AIRestorationProvider, AIRestorationResult


def create_sample_jpeg(width: int = 128, height: int = 128, color=(45, 120, 200)) -> bytes:
    """Generates a genuine valid JPEG image."""
    bio = io.BytesIO()
    img = Image.new("RGB", (width, height), color=color)
    d = ImageDraw.Draw(img)
    d.rectangle([(20, 20), (width - 20, height - 20)], fill=(220, 80, 50))
    d.text((30, 50), "AUTHENTIC PIXELS", fill=(255, 255, 255))
    img.save(bio, format="JPEG", quality=85)
    return bio.getvalue()


class FailingAIProvider(AIRestorationProvider):
    """Simulated provider that triggers an outage or rate limit error."""

    @property
    def provider_name(self) -> str:
        return "failing_ai_service"

    def restore_image(self, original_image, damage_mask, prompt: str = "") -> AIRestorationResult:
        return AIRestorationResult(
            success=False,
            restored_image=None,
            restored_bytes=None,
            provider_name=self.provider_name,
            error_message="503 Service Unavailable: upstream AI inpainting rate limit exceeded"
        )


@pytest.fixture
def recovery_svc():
    return AIRecoveryService()


# --------------------------------------------------------------------------
# Test 1: Healthy JPEG -> No AI call
# --------------------------------------------------------------------------
def test_1_healthy_jpeg_no_ai_call(recovery_svc):
    """
    If the image can be recovered exactly (0% corruption),
    DO NOT call the AI API. Must report exact_recovery with 100% authentic data.
    """
    healthy_bytes = create_sample_jpeg()
    report = recovery_svc.recover_image(
        file_bytes=healthy_bytes,
        filename="healthy_sample.jpg",
        enable_ai=True,
        provider_name="mock",
        test_mode=True
    )

    assert report["corruptionDetected"] is False
    assert report["corruptionPercentage"] == 0.0
    assert report["exactRecoveryPercentage"] == 100.0
    assert report["fragmentRecoveryPercentage"] == 0.0
    assert report["aiRestorationPercentage"] == 0.0
    assert report["aiUsed"] is False
    assert report["resultType"] == "exact_recovery"
    assert report["confidence"] == 1.0
    assert report["recoveredFilePath"] is not None
    assert Path(report["recoveredFilePath"]).exists()

    # Check test mode ledger
    audit = report["testModeData"]
    assert audit["ai_api_status"] == "bypassed_healthy"
    assert audit["recovery_method"] == "exact_recovery"
    assert audit["validation_result"] is True


# --------------------------------------------------------------------------
# Test 2: Slightly corrupted JPEG -> Structural recovery
# --------------------------------------------------------------------------
def test_2_slightly_corrupted_jpeg_structural_recovery(recovery_svc):
    """
    Slightly corrupted JPEG missing EOI marker (\xFF\xD9) at the end.
    Structural repair should restore the marker without requiring AI inpainting.
    """
    clean_bytes = create_sample_jpeg()
    # Strip the trailing EOI marker
    assert clean_bytes.endswith(b"\xFF\xD9")
    stripped_bytes = clean_bytes[:-2]

    report = recovery_svc.recover_image(
        file_bytes=stripped_bytes,
        filename="missing_eoi.jpg",
        enable_ai=True,
        provider_name="mock",
        test_mode=True
    )

    # Structural repair should succeed
    assert report["corruptionDetected"] is True
    assert report["exactRecoveryPercentage"] >= 95.0
    # Because structural repair completely solved the missing marker, AI is not called
    assert report["aiUsed"] is False
    assert report["resultType"] in ("fragment_recovery", "exact_recovery")
    assert report["validation"]["decoder_success"] is True
    assert Path(report["recoveredFilePath"]).exists()


# --------------------------------------------------------------------------
# Test 3: Partially corrupted JPEG -> Fragment recovery + AI restoration
# --------------------------------------------------------------------------
def test_3_partially_corrupted_jpeg_ai_restoration(recovery_svc):
    """
    Partially corrupted JPEG where bottom 30% of bitstream is truncated.
    Engine must preserve authentic top portion and inpaint damaged region with AI.
    Metrics must distinguish exact authentic data vs AI restored data.
    """
    clean_bytes = create_sample_jpeg(width=160, height=160)
    # Truncate 35% of payload
    cutoff = int(len(clean_bytes) * 0.65)
    truncated_bytes = clean_bytes[:cutoff]

    report = recovery_svc.recover_image(
        file_bytes=truncated_bytes,
        filename="truncated_scene.jpg",
        enable_ai=True,
        provider_name="mock",
        test_mode=True
    )

    assert report["corruptionDetected"] is True
    assert report["corruptionPercentage"] > 0.0
    assert report["exactRecoveryPercentage"] > 0.0
    assert report["aiRestorationPercentage"] > 0.0
    assert report["aiUsed"] is True
    assert report["resultType"] == "partial_ai_restoration"
    # Never claim 100% original data
    assert report["exactRecoveryPercentage"] < 100.0
    assert report["aiRestorationPercentage"] + report["exactRecoveryPercentage"] + report["fragmentRecoveryPercentage"] <= 101.0
    assert "synthetic" in report["message"].lower() or "disclaimer" in report
    assert Path(report["recoveredFilePath"]).exists()

    # Check test audit record
    audit = report["testModeData"]
    assert audit["recovery_method"] == "ai_restoration"
    assert audit["ai_api_status"] == "success"
    assert audit["validation_result"] is True


# --------------------------------------------------------------------------
# Test 4: Completely invalid file -> Reject / Unrecoverable
# --------------------------------------------------------------------------
def test_4_completely_invalid_file_rejected(recovery_svc):
    """
    Arbitrary non-image binary data (e.g. random text/shell bytes).
    Must be rejected with 'unrecoverable' and never sent to AI API.
    Zero fabricated data.
    """
    garbage_bytes = b"MZ\x90\x00\x03\x00\x00\x00This is not an image file at all!"
    report = recovery_svc.recover_image(
        file_bytes=garbage_bytes,
        filename="malware.bin",
        enable_ai=True,
        provider_name="mock",
        test_mode=True
    )

    assert report["resultType"] == "unrecoverable"
    assert report["corruptionPercentage"] == 100.0
    assert report["exactRecoveryPercentage"] == 0.0
    assert report["aiUsed"] is False
    assert report["confidence"] == 0.0
    assert report["recoveredFilePath"] is None
    assert "zero recoverable image data" in report["message"].lower() or "unrecoverable" in report["status"].lower()


# --------------------------------------------------------------------------
# Test 5: AI API unavailable -> Normal recovery still works
# --------------------------------------------------------------------------
def test_5_ai_api_unavailable_normal_recovery_preserved(recovery_svc, monkeypatch):
    """
    When AI restoration service fails (e.g., HTTP 503 / network timeout),
    the normally recovered file MUST be kept and returned.
    Do not mark the file as unrecoverable solely because AI failed.
    """
    clean_bytes = create_sample_jpeg(width=140, height=140)
    truncated_bytes = clean_bytes[: int(len(clean_bytes) * 0.70)]

    # Mock provider factory to return FailingAIProvider
    monkeypatch.setattr(
        "backend.services.ai_recovery_service.get_ai_provider",
        lambda name=None: FailingAIProvider()
    )

    report = recovery_svc.recover_image(
        file_bytes=truncated_bytes,
        filename="scene_failing_api.jpg",
        enable_ai=True,
        test_mode=True
    )

    assert report["corruptionDetected"] is True
    assert report["aiUsed"] is False
    assert report["resultType"] == "partial_recovery"
    assert report["recoveredFilePath"] is not None
    assert Path(report["recoveredFilePath"]).exists()
    assert report["aiError"] is not None
    assert "rate limit exceeded" in report["aiError"] or "503" in report["aiError"]
    # Check that file was not marked unrecoverable
    assert report["status"] != "unrecoverable"


# --------------------------------------------------------------------------
# Test 6: Missing API key -> Clear configuration error
# --------------------------------------------------------------------------
def test_6_missing_api_key_configuration_error(monkeypatch):
    """
    When an external provider (OpenAI, Gemini) is selected without AI_API_KEY,
    the provider factory or adapter must raise a clear ValueError.
    """
    monkeypatch.setattr(settings, "ai_api_key", "")
    monkeypatch.delenv("AI_API_KEY", raising=False)

    with pytest.raises(ValueError) as excinfo:
        get_ai_provider("openai")

    err_text = str(excinfo.value)
    assert "AI_API_KEY environment variable is required" in err_text
    assert "process.env.AI_API_KEY" in err_text or "AI_API_KEY" in err_text


# --------------------------------------------------------------------------
# Test 7: Large file -> Proper size validation
# --------------------------------------------------------------------------
def test_7_large_file_size_validation(recovery_svc, monkeypatch):
    """
    Files exceeding max_upload_size_mb must be rejected with size validation.
    """
    monkeypatch.setattr(settings, "max_upload_size_mb", 1)  # 1 MB threshold for test
    oversized_bytes = b"X" * (2 * 1024 * 1024)  # 2 MB payload

    report = recovery_svc.recover_image(
        file_bytes=oversized_bytes,
        filename="giant_evidence.jpg",
        enable_ai=True,
        test_mode=True
    )

    assert report["resultType"] == "unrecoverable"
    assert report["status"] == "rejected"
    assert "exceeds maximum authorized limit" in report["message"]
    assert report["recoveredFilePath"] is None


# --------------------------------------------------------------------------
# Test 8: Original file remains unchanged (Immutability)
# --------------------------------------------------------------------------
def test_8_original_file_remains_unchanged(recovery_svc, tmp_path):
    """
    Forensic immutability requirement:
    Never overwrite the original user file. Save AI output as a brand NEW file.
    Input hash must be identical before and after recovery.
    """
    original_data = create_sample_jpeg()
    original_file_path = tmp_path / "original_user_file.jpg"
    original_file_path.write_bytes(original_data)

    initial_hash = hashlib.sha256(original_file_path.read_bytes()).hexdigest()

    report = recovery_svc.recover_image(
        file_bytes=original_file_path.read_bytes(),
        filename=original_file_path.name,
        enable_ai=True,
        provider_name="mock",
        test_mode=True
    )

    # Re-read original file
    post_hash = hashlib.sha256(original_file_path.read_bytes()).hexdigest()

    assert initial_hash == post_hash, "Original file was modified! Immutability violated."
    assert report["recoveredFilePath"] != str(original_file_path)
    if report["recoveredFilePath"]:
        assert Path(report["recoveredFilePath"]).name != original_file_path.name


# --------------------------------------------------------------------------
# Test Mode Audit Ledger Verification
# --------------------------------------------------------------------------
def test_test_mode_audit_ledger(recovery_svc):
    """
    Verifies that test mode records all required audit metrics:
    - input hash
    - output hash
    - file sizes
    - recovery method
    - corruption level
    - AI API status
    - validation result
    """
    data = create_sample_jpeg()
    report = recovery_svc.recover_image(
        file_bytes=data,
        filename="audit_test.jpg",
        enable_ai=True,
        provider_name="mock",
        test_mode=True
    )

    assert "testModeData" in report
    audit = report["testModeData"]
    required_keys = [
        "input_hash",
        "output_hash",
        "input_size_bytes",
        "output_size_bytes",
        "recovery_method",
        "corruption_level_pct",
        "ai_api_status",
        "validation_result",
    ]
    for k in required_keys:
        assert k in audit, f"Missing required test mode audit key: {k}"
        assert audit[k] is not None
