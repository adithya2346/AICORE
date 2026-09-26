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
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from fastapi.responses import FileResponse

from backend.config import settings
from backend.services.ai_recovery_service import AIRecoveryService

router = APIRouter(prefix="/api/recover", tags=["ai_recovery"])
recovery_service = AIRecoveryService()


@router.post("", summary="Recover damaged image with conditional AI restoration")
@router.post("/", summary="Recover damaged image with conditional AI restoration (trailing slash)")
async def recover_image_endpoint(
    file: UploadFile = File(...),
    enable_ai: bool = Form(True),
    provider: Optional[str] = Form(None),
    original_path: Optional[str] = Form(None),
    replace_corrupted: bool = Form(False),
    test_mode: bool = Form(False)
):
    """
    Executes image recovery pipeline:
    1. Validates file size and MIME type.
    2. Performs deep corruption analysis on JPEG/PNG bitstream.
    3. Executes non-destructive structural repair.
    4. Conditionally invokes AI inpainting ONLY if visual damage remains.
    5. Returns an honest forensic recovery report distinguishing exact, fragment, and AI-generated data.
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
