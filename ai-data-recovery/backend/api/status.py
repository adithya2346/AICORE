"""
FastAPI endpoints for recovery jobs querying, pagination, search, status, and dashboard analytics.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from backend.database.database import get_db, check_db_connection
from backend.database.models import RecoveryJob, AuditLog, FileRecord
from backend.database.repository import RecoveryJobRepository, AuditLogRepository

router = APIRouter(prefix="/api/recovery", tags=["status"])


@router.get("/health", summary="PostgreSQL Database Health Check")
def health_check():
    """Verify PostgreSQL connectivity and database status."""
    res = check_db_connection()
    return {
        "status": "online" if res.get("connected") else "degraded",
        "database": res
    }


@router.get("/dashboard", summary="PostgreSQL Aggregated Dashboard Metrics")
def get_dashboard(db: Session = Depends(get_db)):
    """
    Returns real PostgreSQL-aggregated recovery metrics:
    - Total recovery jobs
    - Active jobs
    - Completed recoveries
    - Failed recoveries
    - Average recovery percentage
    - Recent recovery jobs
    - File type distribution
    - Recovery status
    - AI confidence
    - Fragment information
    """
    return RecoveryJobRepository.get_dashboard_stats(db)


@router.get("/jobs", summary="List and Search Recovery Jobs with Pagination")
def list_recovery_jobs(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status (pending, analyzing, scanning, etc.)"),
    file_type: Optional[str] = Query(None, description="Filter by file type (jpeg, png, pdf, etc.)"),
    search: Optional[str] = Query(None, description="Search by job name, file name, or status"),
    sort: str = Query("created_at", description="Sort field (created_at, job_name, status)"),
    order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    format: Optional[str] = Query(None, description="Set to 'list' to return raw array"),
    db: Session = Depends(get_db)
):
    """
    Returns real database information supporting:
    - pagination
    - search
    - filtering by status
    - filtering by file type
    - sorting by date
    """
    res = RecoveryJobRepository.list_jobs(
        db=db,
        page=page,
        limit=limit,
        status=status,
        file_type=file_type,
        search=search,
        sort=sort,
        order=order
    )
    if format == "list":
        return res["items"]
    return res


@router.get("/jobs/{job_id}", summary="Get Complete Recovery Job Details & Audit History")
def get_recovery_job_details(job_id: str, db: Session = Depends(get_db)):
    """
    Returns complete real database information about:
    - uploaded file
    - corruption analysis
    - fragments
    - AI analysis
    - reconstruction
    - validation
    - recovery result
    - audit history
    """
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Recovery job not found")

    file_rec: Optional[FileRecord] = job.files[0] if job.files else None
    frags = file_rec.fragments if file_rec else []
    ai = file_rec.ai_analysis if file_rec else None
    res = file_rec.recovery_results[0] if file_rec and file_rec.recovery_results else None
    logs = AuditLogRepository.get_by_job(db, job.id)

    valid_frags_count = sum(1 for f in frags if f.is_valid)
    reconstructed_frags_count = len(frags)

    file_info = {
        "id": str(file_rec.id) if file_rec else None,
        "name": file_rec.original_name if file_rec else job.target_filename or "evidence.bin",
        "type": file_rec.detected_type if file_rec else job.target_type or "unknown",
        "mime_type": file_rec.mime_type if file_rec else None,
        "size": file_rec.file_size if file_rec else 0,
        "file_hash": file_rec.file_hash if file_rec else None,
        "storage_path": file_rec.storage_path if file_rec else job.source_path,
        "damagePercentage": file_rec.damage_percentage if file_rec else 0.0,
        "status": file_rec.status if file_rec else "uploaded"
    } if file_rec else {
        "name": job.target_filename or Path(job.source_path).name if job.source_path else "evidence.bin",
        "type": job.target_type or "unknown",
        "size": 0,
        "damagePercentage": 0.0
    }

    fragments_info = {
        "detected": len(frags),
        "valid": valid_frags_count,
        "reconstructed": reconstructed_frags_count,
        "items": [
            {
                "id": str(f.id),
                "index": f.fragment_index,
                "offset_start": f.offset_start,
                "offset_end": f.offset_end,
                "size": f.fragment_size,
                "hash": f.fragment_hash,
                "confidence": f.confidence,
                "is_valid": f.is_valid,
                "entropy": f.entropy,
                "type": f.predicted_type
            }
            for f in frags
        ]
    }

    ai_info = {
        "id": str(ai.id) if ai else None,
        "confidence": ai.confidence if ai else 0.0,
        "corruptionType": ai.corruption_type if ai else "none",
        "explanation": ai.explanation if ai else "No visual damage detected.",
        "modelName": ai.model_name if ai else "forensic-ai-v1",
        "damagedRegions": ai.damaged_regions if ai else None,
        "predictedStructure": ai.predicted_structure if ai else None
    } if ai else {
        "confidence": 0.0,
        "corruptionType": "none",
        "explanation": "Pending or not required."
    }

    rec_info = {
        "id": str(res.id) if res else None,
        "percentage": res.recovery_percentage if res else (100.0 if job.status == "completed" else 0.0),
        "validationStatus": res.validation_status if res else ("PASS" if job.status == "completed" else "PENDING"),
        "recoveredPath": res.recovered_path if res else None,
        "recoveredSize": res.recovered_size if res else 0,
        "outputHash": res.output_hash if res else None,
        "validationDetails": res.validation_details if res else None
    }

    audit_history = [
        {
            "id": l.id,
            "action": l.action,
            "details": l.details,
            "timestamp": l.created_at.isoformat() if l.created_at else None
        }
        for l in logs
    ]

    return {
        "id": str(job.id),
        "job_name": job.job_name,
        "status": job.status,
        "current_stage": job.current_stage,
        "progress": job.progress,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "file": file_info,
        "fragments": fragments_info,
        "aiAnalysis": ai_info,
        "recovery": rec_info,
        "audit_history": audit_history
    }


@router.get("/{job_id}/status", summary="Poll Job Operational Status")
def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Retrieve operational progress, current stage, and status of a job."""
    job = RecoveryJobRepository.get_by_id(db, job_id)
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
        "job_id": str(job.id),
        "id": str(job.id),
        "job_name": job.job_name,
        "operation": job.operation,
        "status": job.status,
        "current_stage": job.current_stage,
        "progress": job.progress,
        "error": job.error,
        "source": source_info,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None
    }


@router.post("/cancel/{job_id}", summary="Cancel Active Recovery Job")
def cancel_recovery_job(job_id: str, db: Session = Depends(get_db)):
    """Cancel an ongoing recovery job cooperatively."""
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Recovery job not found")

    if job.status in ("completed", "failed", "cancelled"):
        return {"job_id": str(job.id), "status": job.status, "message": "Job is already terminated."}

    job.status = "failed"
    job.current_stage = "cancelled"
    job.error = "Cancelled by user request."
    db.commit()

    AuditLogRepository.log(
        db=db,
        job_id=job.id,
        action="JOB_CANCELLED",
        details={"reason": "User cancellation via API"}
    )

    return {"job_id": str(job.id), "status": "failed", "message": "Job cancelled."}
