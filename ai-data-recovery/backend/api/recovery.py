"""
FastAPI endpoints for initiating recovery jobs and step-by-step pipeline control.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import uuid
import shutil
from pathlib import Path

from backend.config import settings
from backend.database.database import get_db
from backend.database.models import RecoveryJob, AuditLog
from backend.workers.recovery_worker import RecoveryWorker

router = APIRouter(prefix="/api/recovery", tags=["recovery"])

class StartRecoveryRequest(BaseModel):
    operation: str # 'recover_corrupted', 'recover_deleted'
    source_type: str # 'uploaded_file', 'disk_image', 'partition'
    source_path: str
    target_filename: Optional[str] = None
    target_type: Optional[str] = None

class StartRecoveryResponse(BaseModel):
    job_id: str
    status: str
    message: str

@router.post("/start", response_model=StartRecoveryResponse)
def start_recovery(
    req: StartRecoveryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Initiate an asynchronous forensic recovery job.
    """
    job_id = f"REC-{uuid.uuid4().hex[:8].upper()}"
    
    source_file = Path(req.source_path)
    if not source_file.exists():
        # Check workspace input dir
        alt_path = settings.input_dir / req.source_path
        if alt_path.exists():
            source_file = alt_path
        else:
            raise HTTPException(status_code=400, detail=f"Authorized source does not exist: {req.source_path}")

    new_job = RecoveryJob(
        id=job_id,
        operation=req.operation,
        source_type=req.source_type,
        source_path=str(source_file.resolve()),
        target_filename=req.target_filename,
        target_type=req.target_type,
        status="created",
        current_stage="created",
        progress=0
    )
    db.add(new_job)

    audit = AuditLog(
        job_id=job_id,
        action="job_created",
        details=f"Source: {source_file}, Operation: {req.operation}"
    )
    db.add(audit)
    db.commit()

    # Launch worker in background
    worker = RecoveryWorker(job_id)
    background_tasks.add_task(worker.run)

    return StartRecoveryResponse(
        job_id=job_id,
        status="created",
        message="Recovery job initialized and dispatched to background processing."
    )

@router.post("/upload")
async def upload_evidence_file(
    file: UploadFile = File(...),
    operation: str = Form("recover_corrupted"),
    target_type: Optional[str] = Form(None)
):
    """
    Upload an authorized damaged file or disk image for recovery analysis.
    """
    dest_path = settings.input_dir / file.filename
    with open(dest_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    return {
        "status": "uploaded",
        "file_name": file.filename,
        "source_path": str(dest_path.resolve()),
        "operation": operation,
        "target_type": target_type
    }

@router.post("/{job_id}/scan")
def trigger_scan(job_id: str, db: Session = Depends(get_db)):
    """Trigger manual re-scan stage on an active job."""
    job = db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "stage": "scanning", "status": job.status}

@router.post("/{job_id}/analyze")
def trigger_analysis(job_id: str, db: Session = Depends(get_db)):
    """Trigger fragment relationship analysis."""
    job = db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "stage": "fragment_analysis", "status": job.status}

@router.post("/{job_id}/reconstruct")
def trigger_reconstruction(job_id: str, db: Session = Depends(get_db)):
    """Trigger sequence reconstruction."""
    job = db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "stage": "reconstructing", "status": job.status}

@router.post("/{job_id}/validate")
def trigger_validation(job_id: str, db: Session = Depends(get_db)):
    """Trigger validator stage."""
    job = db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "stage": "validating", "status": job.status}
