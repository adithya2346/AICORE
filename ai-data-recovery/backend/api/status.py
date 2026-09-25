"""
FastAPI endpoints for job status querying, progress tracking, and cancellation.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from backend.database.database import get_db
from backend.database.models import RecoveryJob, SourceAudit, AuditLog

router = APIRouter(prefix="/api/recovery", tags=["status"])

@router.get("/jobs")
def list_recovery_jobs(limit: int = 50, db: Session = Depends(get_db)):
    """List recent recovery jobs for dashboard monitoring."""
    jobs = db.query(RecoveryJob).order_by(RecoveryJob.created_at.desc()).limit(limit).all()
    return [
        {
            "job_id": j.id,
            "operation": j.operation,
            "source_type": j.source_type,
            "source_path": j.source_path,
            "target_filename": j.target_filename,
            "target_type": j.target_type,
            "status": j.status,
            "current_stage": j.current_stage,
            "progress": j.progress,
            "created_at": j.created_at.isoformat() if j.created_at else None
        }
        for j in jobs
    ]

@router.get("/{job_id}/status")
def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Retrieve current progress, stage, and operational status of a job."""
    job = db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recovery job not found")

    source_info = None
    if job.source:
        source_info = {
            "source_path": job.source.source_path,
            "source_sha256": job.source.source_sha256,
            "source_size": job.source.source_size,
            "source_type": job.source.source_type,
            "sector_size": job.source.sector_size,
            "filesystem_detected": job.source.filesystem_detected,
            "is_read_only": job.source.is_read_only,
            "acquired_at": job.source.acquired_at.isoformat() if job.source.acquired_at else None
        }

    return {
        "job_id": job.id,
        "operation": job.operation,
        "status": job.status,
        "current_stage": job.current_stage,
        "progress": job.progress,
        "error": job.error,
        "source": source_info,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None
    }

@router.post("/cancel/{job_id}")
def cancel_recovery_job(job_id: str, db: Session = Depends(get_db)):
    """Cancel an ongoing recovery job cooperatively."""
    job = db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recovery job not found")

    if job.status in ("completed", "failed", "cancelled"):
        return {"job_id": job_id, "status": job.status, "message": "Job is already terminated."}

    job.status = "cancelled"
    job.current_stage = "cancelled"
    db.commit()

    audit = AuditLog(
        job_id=job_id,
        action="job_cancelled",
        details="Cancellation requested via API"
    )
    db.add(audit)
    db.commit()

    return {"job_id": job_id, "status": "cancelled", "message": "Job cancellation flag set."}
