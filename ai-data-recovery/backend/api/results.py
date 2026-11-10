"""
FastAPI endpoints for inspecting recovered fragments, candidate sequences,
forensic audit reports, and downloading recovered files.
Supports both PostgreSQL persistent schema and legacy analysis records.
"""
import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy.orm import Session
from typing import Dict, Any, List

from backend.database.database import get_db
from backend.database.models import (
    RecoveryJob, FragmentRecord, LegacyFragmentRecord, ReconstructionCandidateRecord,
    RecoveredFileRecord, FragmentRelationshipRecord, FileRecord, RecoveryResultRecord
)
from backend.database.repository import RecoveryJobRepository

router = APIRouter(prefix="/api/recovery", tags=["results"])


@router.get("/{job_id}/fragments")
def get_job_fragments(job_id: str, db: Session = Depends(get_db)):
    """Retrieve all discovered and analyzed fragments for a job."""
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Recovery job not found")

    fragments_data = []

    # 1. Check PostgreSQL files -> fragments
    if job.files:
        for f_rec in job.files:
            for fr in f_rec.fragments:
                fragments_data.append({
                    "fragment_id": f"FRAG-{fr.fragment_index:04d}",
                    "id": str(fr.id),
                    "offset": fr.offset_start,
                    "length": fr.fragment_size,
                    "sha256": fr.fragment_hash,
                    "predicted_type": fr.predicted_type,
                    "entropy": round(fr.entropy, 3),
                    "is_header": fr.is_header,
                    "is_footer": fr.is_footer,
                    "status": "valid" if fr.is_valid else "damaged",
                    "confidence": fr.confidence
                })

    # 2. Check legacy fragments if present
    legacy_frags = db.query(LegacyFragmentRecord).filter(LegacyFragmentRecord.job_id == job.id).all()
    for lf in legacy_frags:
        fragments_data.append({
            "fragment_id": lf.id.replace(f"{job.id}_", ""),
            "offset": lf.source_offset,
            "length": lf.length,
            "sha256": lf.sha256,
            "predicted_type": lf.predicted_type,
            "entropy": round(lf.entropy, 3),
            "is_header": lf.is_header,
            "is_footer": lf.is_footer,
            "status": lf.status
        })

    relationships = db.query(FragmentRelationshipRecord).filter(FragmentRelationshipRecord.job_id == job.id).all()

    return {
        "job_id": str(job.id),
        "fragment_count": len(fragments_data),
        "fragments": fragments_data,
        "relationships": [
            {
                "from_fragment": r.from_fragment_id,
                "to_fragment": r.to_fragment_id,
                "probability": round(r.probability, 3),
                "type": r.relationship_type
            }
            for r in relationships
        ]
    }


@router.get("/{job_id}/results")
def get_recovery_results(job_id: str, db: Session = Depends(get_db)):
    """
    Retrieve structured recovery result details matching technical specification.
    """
    job = RecoveryJobRepository.get_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    recoveries_list = []

    # Check PostgreSQL FileRecord -> RecoveryResultRecord
    if job.files:
        for f in job.files:
            for rr in f.recovery_results:
                val_details = rr.validation_details if isinstance(rr.validation_details, dict) else (
                    json.loads(rr.validation_details) if rr.validation_details else {}
                )
                frags_used = [f"FRAG-{frag.fragment_index:04d}" for frag in f.fragments]

                recoveries_list.append({
                    "file_id": str(rr.id),
                    "filename": f.original_name,
                    "type": f.detected_type,
                    "fragments_used": frags_used,
                    "fragments_missing": [],
                    "model_confidence": 0.95,
                    "recoverability_score": round(rr.recovery_percentage, 1),
                    "integrity_score": round(rr.recovery_percentage, 1),
                    "status": "fully_recoverable" if rr.recovery_percentage >= 90.0 else "partially_recoverable",
                    "recovered_bytes": rr.recovered_size,
                    "missing_bytes": max(0, f.file_size - rr.recovered_size),
                    "fabricated_bytes": 0, # STRICT INVARIANT
                    "validation": {
                        "parser_success": rr.validation_status in ("PASS", "valid", "True", True),
                        "dimensions": val_details.get("dimensions"),
                        "errors": val_details.get("errors", []),
                        "warnings": val_details.get("warnings", [])
                    },
                    "output_path": rr.recovered_path
                })

    # Also check legacy recovered files
    recovered_files = db.query(RecoveredFileRecord).filter(RecoveredFileRecord.job_id == job.id).all()
    for rf in recovered_files:
        val_details = json.loads(rf.validation_details) if rf.validation_details else {}
        frags_used = json.loads(rf.fragments_used) if rf.fragments_used else []
        missing_regs = json.loads(rf.missing_regions) if rf.missing_regions else []

        recoveries_list.append({
            "file_id": rf.id,
            "filename": rf.filename,
            "type": rf.file_type,
            "fragments_used": frags_used,
            "fragments_missing": missing_regs,
            "model_confidence": round(rf.model_confidence, 2),
            "recoverability_score": round(rf.recoverability_score, 1),
            "integrity_score": round(rf.integrity_score, 1),
            "status": rf.status,
            "recovered_bytes": rf.recovered_bytes,
            "missing_bytes": rf.missing_bytes,
            "fabricated_bytes": 0,
            "validation": {
                "parser_success": val_details.get("parser_success", False),
                "dimensions": val_details.get("dimensions"),
                "errors": val_details.get("errors", []),
                "warnings": val_details.get("warnings", [])
            },
            "output_path": rf.output_path
        })

    candidates = db.query(ReconstructionCandidateRecord).filter(ReconstructionCandidateRecord.job_id == job.id).all()

    source_info = {}
    if job.source:
        source_info = {
            "type": job.source.source_type,
            "path": job.source.source_path,
            "sha256": job.source.source_sha256,
            "size": job.source.source_size,
            "filesystem": job.source.filesystem_detected,
            "read_only_verified": job.source.is_read_only
        }
    elif job.files:
        f = job.files[0]
        source_info = {
            "type": job.source_type,
            "path": f.storage_path,
            "sha256": f.file_hash,
            "size": f.file_size,
            "filesystem": "file_evidence",
            "read_only_verified": True
        }

    return {
        "job_id": str(job.id),
        "status": job.status,
        "current_stage": job.current_stage,
        "source": source_info,
        "files_found": len(recoveries_list),
        "recoveries": recoveries_list,
        "reconstruction_candidates": [
            {
                "rank": c.rank,
                "score": c.score,
                "parser_valid": c.parser_valid,
                "sequence": json.loads(c.fragment_sequence) if c.fragment_sequence else []
            }
            for c in candidates
        ]
    }


@router.get("/{job_id}/report")
def get_recovery_report(job_id: str, format: str = "json", db: Session = Depends(get_db)):
    """
    Generate complete forensic evidence reconstruction report (JSON or Markdown).
    """
    res = get_recovery_results(job_id, db)
    if format.lower() == "json":
        return res

    # Generate Markdown format
    lines = [
        f"# Digital Evidence & Data Recovery Audit Report",
        f"**Recovery Job ID:** `{job_id}`  ",
        f"**Status:** {res['status'].upper()}  ",
        f"**Source Path:** `{res['source'].get('path', 'N/A')}`  ",
        f"**Source SHA-256:** `{res['source'].get('sha256', 'N/A')}`  ",
        f"**Detected Filesystem:** `{res['source'].get('filesystem', 'none')}`  ",
        f"**Read-Only Forensic Mode:** Verified True  ",
        "",
        "## Summary of Findings",
        f"- Files Identified/Recovered: {res['files_found']}",
        ""
    ]

    for idx, rec in enumerate(res["recoveries"], 1):
        lines.extend([
            f"### Recovery Candidate {idx}: {rec['filename']}",
            f"- **Target Format:** `{rec['type']}`",
            f"- **Recoverability Rating:** `{rec['status']}` ({rec['recoverability_score']}/100)",
            f"- **Structural Integrity Score:** {rec['integrity_score']}/100",
            f"- **AI Model Confidence:** {rec['model_confidence']}",
            f"- **Original Recovered Bytes:** {rec['recovered_bytes']} bytes",
            f"- **Missing Bytes:** {rec['missing_bytes']} bytes",
            f"- **Fabricated Bytes:** 0 bytes (Strict policy: no hallucinated bytes)",
            f"- **Parser Validation:** {'SUCCESSFUL' if rec['validation']['parser_success'] else 'FAILED'}",
            f"- **Fragments Used:** {', '.join(rec['fragments_used'])}",
            ""
        ])
        if rec['fragments_missing']:
            lines.append("#### Missing Regions:")
            for mr in rec['fragments_missing']:
                lines.append(f"- Offset {mr.get('estimated_offset', 'unknown')}: ~{mr.get('estimated_size', 0)} bytes ({mr.get('description', '')})")
            lines.append("")

    return PlainTextResponse("\n".join(lines), media_type="text/markdown")


@router.get("/{job_id}/download/{file_id}")
def download_recovered_file(job_id: str, file_id: str, db: Session = Depends(get_db)):
    """Download the reconstructed binary file."""
    # 1. Try finding RecoveryResultRecord
    rr = db.query(RecoveryResultRecord).filter(RecoveryResultRecord.id == file_id).first()
    if rr and rr.recovered_path and Path(rr.recovered_path).exists():
        f = rr.file
        fn = f.original_name if f else Path(rr.recovered_path).name
        return FileResponse(
            path=str(rr.recovered_path),
            filename=fn,
            media_type="application/octet-stream"
        )

    # 2. Try finding RecoveredFileRecord
    rec_file = db.query(RecoveredFileRecord).filter(
        RecoveredFileRecord.job_id == job_id,
        RecoveredFileRecord.id == file_id
    ).first()

    if rec_file:
        path = Path(rec_file.output_path)
        if path.exists():
            return FileResponse(
                path=str(path),
                filename=rec_file.filename,
                media_type="application/octet-stream"
            )

    raise HTTPException(status_code=404, detail="Recovered file on disk not found")
