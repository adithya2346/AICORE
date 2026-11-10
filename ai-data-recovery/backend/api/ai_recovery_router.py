"""
FastAPI Endpoints for AI-Assisted Image Recovery:
- POST /api/recover: Upload damaged image, analyze corruption, conditionally restore via AI, return report
- GET /api/recover/download/{filename}: Download/preview recovered image
- GET /api/recover/health: Health check and provider configuration status (without exposing secrets)
"""
import os
import shutil
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status, Depends
from fastapi.responses import FileResponse

from backend.config import settings
from backend.services.ai_recovery_service import AIRecoveryService

router = APIRouter(prefix="/api/recover", tags=["ai_recovery"])
recovery_service = AIRecoveryService()


from backend.database.database import get_db
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger("ai_recovery_router")

@router.post("", summary="Recover damaged image with conditional AI restoration")
@router.post("/", summary="Recover damaged image with conditional AI restoration (trailing slash)")
async def recover_image_endpoint(
    file: UploadFile = File(...),
    enable_ai: bool = Form(True),
    provider: Optional[str] = Form(None),
    original_path: Optional[str] = Form(None),
    replace_corrupted: bool = Form(False),
    test_mode: bool = Form(False),
    db: Session = Depends(get_db)
):
    """
    Executes image recovery pipeline:
    1. Validates file size and MIME type.
    2. Performs deep corruption analysis on JPEG/PNG bitstream.
    3. Executes non-destructive structural repair.
    4. Conditionally invokes AI inpainting ONLY if visual damage remains.
    5. Returns an honest forensic recovery report distinguishing exact, fragment, and AI-generated data.
    6. Persists complete recovery results into PostgreSQL.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid file upload is required."
        )

    # Read uploaded bytes into memory (limited by max_upload_size_mb)
    content = await file.read()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024

    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size limit of {settings.max_upload_size_mb} MB."
        )

    # Process recovery
    report = recovery_service.recover_image(
        file_bytes=content,
        filename=file.filename,
        enable_ai=enable_ai,
        provider_name=provider,
        test_mode=test_mode
    )

    # Persist record into PostgreSQL
    try:
        from backend.database.repository import (
            RecoveryJobRepository, FileRepository, FragmentRepository,
            AIAnalysisRepository, RecoveryResultRepository, AuditLogRepository
        )
        from backend.security.hashing import calculate_bytes_sha256

        file_hash = calculate_bytes_sha256(content)
        job_status = "completed" if report.get("status") in ("success", "partial_success") else "failed"
        job = RecoveryJobRepository.create_job(
            db=db,
            job_name=f"AI Image Recovery: {file.filename}",
            status=job_status,
            operation="recover_corrupted",
            source_type="uploaded_file",
            source_path=str(settings.input_dir / file.filename),
            target_filename=file.filename,
            target_type=report.get("fileType", "JPEG")
        )

        corr_pct = float(report.get("corruptionPercentage", 0.0))
        file_rec = FileRepository.create_file(
            db=db,
            job_id=job.id,
            original_name=file.filename,
            detected_type=report.get("fileType", "JPEG"),
            mime_type=file.content_type or f"image/{report.get('fileType', 'jpeg').lower()}",
            file_size=len(content),
            file_hash=file_hash,
            storage_path=report.get("recoveredFilePath") or str(settings.input_dir / file.filename),
            damage_percentage=corr_pct,
            status=job_status
        )

        # Store fragments
        for idx, frag_info in enumerate(report.get("fragments", []), 1):
            FragmentRepository.create_fragment(
                db=db,
                file_id=file_rec.id,
                fragment_index=idx,
                offset_start=0,
                offset_end=frag_info.get("size_bytes", 4096),
                fragment_size=frag_info.get("size_bytes", 4096),
                fragment_hash=file_hash[:32],
                confidence=100.0 if frag_info.get("is_authentic") else 85.0,
                is_valid=frag_info.get("is_authentic", True)
            )

        # Store AI Analysis
        ai_conf_val = float(report.get("confidence", 0.9))
        ai_conf_pct = ai_conf_val * 100.0 if ai_conf_val <= 1.0 else ai_conf_val
        AIAnalysisRepository.create_or_update(
            db=db,
            file_id=file_rec.id,
            detected_file_type=report.get("fileType", "JPEG"),
            corruption_type="visual_and_structural" if corr_pct > 0 else "none",
            confidence=min(100.0, max(0.0, ai_conf_pct)),
            explanation=report.get("message", "Forensic analysis completed.")
        )

        # Store Recovery Result
        rec_pct = float(report.get("successRate") or report.get("success_rate") or report.get("exactRecoveryPercentage") or 100.0)
        rec_path = report.get("recoveredFilePath") or str(settings.output_dir / file.filename)
        RecoveryResultRepository.create_result(
            db=db,
            file_id=file_rec.id,
            recovered_path=rec_path,
            recovered_size=report.get("recoveredFileSize", len(content)),
            recovery_percentage=min(100.0, max(0.0, rec_pct)),
            validation_status="PASS" if report.get("validation", {}).get("is_valid", True) else "PARTIAL",
            output_hash=file_hash,
            validation_details=report.get("validation")
        )

        AuditLogRepository.log(
            db=db,
            job_id=job.id,
            action="RECOVERY_COMPLETED",
            details={
                "resultType": report.get("resultType"),
                "recovery_percentage": rec_pct,
                "aiUsed": report.get("aiUsed", False)
            }
        )
        report["job_id"] = str(job.id)
        report["id"] = str(job.id)
    except Exception as db_err:
        logger.warning(f"Could not persist recovery report to database: {db_err}")

    # Add download URL if a recovered file was generated
    if report.get("recoveredFileName"):
        report["downloadUrl"] = f"/api/recover/download/{report['recoveredFileName']}"
        report["previewUrl"] = f"/api/recover/preview/{report['recoveredFileName']}"

        # If user requested replacement and original file exists on local system
        if replace_corrupted and original_path:
            orig = Path(original_path)
            rec_file = Path(report.get("recoveredFilePath", ""))
            if orig.exists() and rec_file.exists():
                try:
                    # Clean up any leftover backup file
                    backup = orig.with_name(f"{orig.stem}_corrupted_backup{orig.suffix}")
                    if backup.exists():
                        try:
                            backup.unlink()
                        except Exception:
                            pass
                    shutil.copy2(rec_file, orig)
                    report["replacedOriginal"] = True
                    report["recoveredFilePath"] = str(orig.resolve())
                except Exception as ex:
                    report["replaceError"] = str(ex)

    return report


from pydantic import BaseModel

class ReplaceFileRequest(BaseModel):
    recovered_filename: str
    target_path: str


@router.post("/replace", summary="Replace original corrupted file with recovered file")
def replace_corrupted_file(req: ReplaceFileRequest):
    """Replaces the corrupted file on disk with the recovered file (single original file output)."""
    safe_rec_name = Path(req.recovered_filename).name
    rec_path = settings.output_dir / safe_rec_name
    if not rec_path.exists():
        raise HTTPException(status_code=404, detail="Recovered file not found.")

    target = Path(req.target_path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Target corrupted file '{target}' not found.")

    # Clean up any leftover backup file
    backup_name = f"{target.stem}_corrupted_backup{target.suffix}"
    backup_path = target.with_name(backup_name)
    if backup_path.exists():
        try:
            backup_path.unlink()
        except Exception:
            pass

    shutil.copy2(rec_path, target)

    return {
        "status": "success",
        "message": f"Corrupted file '{target.name}' successfully replaced with recovered file.",
        "target_path": str(target.resolve())
    }


@router.get("/download/{filename}", summary="Download recovered file")
def download_recovered_file(filename: str):
    """Safely serves a recovered or AI-restored image file from the output directory."""
    # Sanitize path to prevent directory traversal
    safe_filename = Path(filename).name
    target_path = settings.output_dir / safe_filename

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovered file '{safe_filename}' not found."
        )

    media_type = "image/png" if safe_filename.lower().endswith(".png") else "image/jpeg"
    return FileResponse(
        path=str(target_path.resolve()),
        filename=safe_filename,
        media_type=media_type
    )


@router.get("/preview/{filename}", summary="Stream recovered image for browser preview")
def preview_recovered_file(filename: str):
    """Streams the image inline for before/after comparison in web browsers."""
    safe_filename = Path(filename).name
    target_path = settings.output_dir / safe_filename

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Preview file '{safe_filename}' not found."
        )

    media_type = "image/png" if safe_filename.lower().endswith(".png") else "image/jpeg"
    return FileResponse(
        path=str(target_path.resolve()),
        media_type=media_type,
        content_disposition_type="inline"
    )


@router.get("/config-status", summary="Check AI provider status without exposing API key")
def get_ai_config_status():
    """
    Returns public non-sensitive configuration status.
    Security policy: NEVER expose or return actual API keys.
    """
    has_key = bool(settings.ai_api_key and len(settings.ai_api_key.strip()) > 0)
    return {
        "provider": settings.ai_provider,
        "model": settings.ai_model,
        "is_configured": has_key,
        "key_present": has_key,
        "max_upload_size_mb": settings.max_upload_size_mb,
    }
