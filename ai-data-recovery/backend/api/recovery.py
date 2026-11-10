"""
FastAPI endpoints for initiating recovery jobs, file uploads, and pipeline control.
Integrates directly with PostgreSQL via repository and workflow services.
"""
import uuid
import shutil
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.config import settings
from backend.database.database import get_db
from backend.database.models import RecoveryJob
from backend.database.repository import RecoveryJobRepository, FileRepository, AuditLogRepository
from backend.services.recovery_service import DatabaseRecoveryWorkflow
from backend.workers.recovery_worker import RecoveryWorker

router = APIRouter(prefix="/api/recovery", tags=["recovery"])


class StartRecoveryRequest(BaseModel):
    operation: str = "recover_corrupted" # 'recover_corrupted', 'recover_deleted'
    source_type: str = "uploaded_file" # 'uploaded_file', 'disk_image', 'partition'
    source_path: str
    target_filename: Optional[str] = None
    target_type: Optional[str] = None
    job_name: Optional[str] = None


class StartRecoveryResponse(BaseModel):
    job_id: str
    status: str
    message: str


@router.post("/jobs/upload", summary="Upload and execute complete 15-step recovery workflow")
async def upload_and_recover_file(
    file: UploadFile = File(...),
    job_name: Optional[str] = Form(None),
    target_format: Optional[str] = Form(None),
    enable_ai: bool = Form(True),
    db: Session = Depends(get_db)
):
    """
    Executes complete 15-step recovery workflow directly into PostgreSQL:
    1. Create recovery_job
    2. Create files record
    3. Calculate file hash
    4. Detect file type
    5. Store file metadata
    6. Start recovery processing
    7. Detect fragments
    8. Save fragment metadata
    9. Run AI analysis
    10. Save AI analysis
    11. Reconstruct file
    12. Validate reconstructed file
    13. Save recovery results
    14. Update recovery_jobs status
    15. Create audit_logs
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="A valid file is required.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    workflow = DatabaseRecoveryWorkflow(db)
    result = workflow.process_file_recovery(
        file_bytes=content,
        original_filename=file.filename,
        job_name=job_name,
        target_format=target_format,
        enable_ai=enable_ai
    )
    return result


@router.post("/start", response_model=StartRecoveryResponse, summary="Initiate asynchronous recovery job")
def start_recovery(
    req: StartRecoveryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Initiate an asynchronous forensic recovery job persisted in PostgreSQL.
    """
    source_file = Path(req.source_path)
    if not source_file.exists():
        # Check workspace input dir
        alt_path = settings.input_dir / req.source_path
        if alt_path.exists():
            source_file = alt_path
        else:
            raise HTTPException(status_code=400, detail=f"Authorized source does not exist: {req.source_path}")

    job_title = req.job_name or f"Recovery of {source_file.name}"
    new_job = RecoveryJobRepository.create_job(
        db=db,
        job_name=job_title,
        status="pending",
        operation=req.operation,
        source_type=req.source_type,
        source_path=str(source_file.resolve()),
        target_filename=req.target_filename or source_file.name,
        target_type=req.target_type
    )

    # Audit: JOB_CREATED
    AuditLogRepository.log(
        db=db,
        job_id=new_job.id,
        action="JOB_CREATED",
        details={
            "source_path": str(source_file.resolve()),
            "operation": req.operation,
            "status": "pending"
        }
    )

    # Launch worker in background
    worker = RecoveryWorker(str(new_job.id))
    background_tasks.add_task(worker.run)

    return StartRecoveryResponse(
        job_id=str(new_job.id),
        status="pending",
        message="Recovery job initialized and dispatched to background processing."
    )


@router.post("/upload", summary="Upload evidence file into storage and create tracking record")
async def upload_evidence_file(
    file: UploadFile = File(...),
    operation: str = Form("recover_corrupted"),
    target_type: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Upload an authorized damaged file or disk image for recovery analysis.
    Creates job & file records in PostgreSQL with physical storage persistence.
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Valid file upload is required.")

    dest_path = settings.input_dir / file.filename
    content = await file.read()
    with open(dest_path, "wb") as buffer:
        buffer.write(content)

    job = RecoveryJobRepository.create_job(
        db=db,
        job_name=f"Evidence: {file.filename}",
        status="pending",
        operation=operation,
        source_type="uploaded_file",
        source_path=str(dest_path.resolve()),
        target_filename=file.filename,
        target_type=target_type
    )

    # Audit: FILE_UPLOADED
    AuditLogRepository.log(
        db=db,
        job_id=job.id,
        action="FILE_UPLOADED",
        details={
            "file_name": file.filename,
            "file_size": len(content),
            "source_path": str(dest_path.resolve())
        }
    )

    return {
        "status": "uploaded",
        "job_id": str(job.id),
        "file_name": file.filename,
        "source_path": str(dest_path.resolve()),
        "operation": operation,
        "target_type": target_type
    }


@router.post("/{job_id}/scan")
def trigger_scan(job_id: str, db: Session = Depends(get_db)):
    """Trigger manual re-scan stage on an active job."""
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    RecoveryJobRepository.update_status(db, job.id, "scanning", current_stage="scanning")
    AuditLogRepository.log(db, job.id, "SCAN_TRIGGERED", {"stage": "scanning"})
    return {"job_id": str(job.id), "stage": "scanning", "status": job.status}


@router.post("/{job_id}/analyze")
def trigger_analysis(job_id: str, db: Session = Depends(get_db)):
    """Trigger fragment relationship analysis."""
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    RecoveryJobRepository.update_status(db, job.id, "analyzing", current_stage="analyzing")
    AuditLogRepository.log(db, job.id, "ANALYSIS_TRIGGERED", {"stage": "analyzing"})
    return {"job_id": str(job.id), "stage": "analyzing", "status": job.status}


@router.post("/{job_id}/reconstruct")
def trigger_reconstruction(job_id: str, db: Session = Depends(get_db)):
    """Trigger sequence reconstruction."""
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    RecoveryJobRepository.update_status(db, job.id, "reconstructing", current_stage="reconstructing")
    AuditLogRepository.log(db, job.id, "RECONSTRUCTION_TRIGGERED", {"stage": "reconstructing"})
    return {"job_id": str(job.id), "stage": "reconstructing", "status": job.status}


@router.post("/{job_id}/validate")
def trigger_validation(job_id: str, db: Session = Depends(get_db)):
    """Trigger validator stage."""
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    RecoveryJobRepository.update_status(db, job.id, "validating", current_stage="validating")
    AuditLogRepository.log(db, job.id, "VALIDATION_TRIGGERED", {"stage": "validating"})
    return {"job_id": str(job.id), "stage": "validating", "status": job.status}
