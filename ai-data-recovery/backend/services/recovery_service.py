"""
PostgreSQL-Integrated Recovery Service.
Executes the full 15-step recovery workflow:
1. Create a recovery_job.
2. Create a files record.
3. Calculate the file hash.
4. Detect file type.
5. Store file metadata.
6. Start recovery processing.
7. Detect fragments.
8. Save fragment metadata to fragments.
9. Run AI analysis.
10. Save AI analysis to ai_analysis.
11. Reconstruct the file.
12. Validate the reconstructed file.
13. Save recovery information to recovery_results.
14. Update recovery_jobs.status.
15. Create audit_logs for important operations.
"""
import os
import uuid
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database.repository import (
    UserRepository, RecoveryJobRepository, FileRepository,
    FragmentRepository, AIAnalysisRepository, RecoveryResultRepository,
    AuditLogRepository
)
from backend.security.hashing import calculate_file_sha256, calculate_bytes_sha256
from backend.recovery.scanner import calculate_entropy
from backend.recovery.fragments import slice_bytes_into_fragments
from backend.ml.classifier import file_classifier
from backend.recovery.reconstruction import ReconstructionEngine
from backend.recovery.confidence import ConfidenceEngine
from backend.services.ai_recovery_service import AIRecoveryService

logger = logging.getLogger("recovery_service")


class DatabaseRecoveryWorkflow:
    """Orchestrates end-to-end recovery pipeline with persistent PostgreSQL storage."""

    def __init__(self, db: Session):
        self.db = db
        self.ai_svc = AIRecoveryService()

    def process_file_recovery(
        self,
        file_bytes: bytes,
        original_filename: str,
        user_id: Optional[Any] = None,
        job_name: Optional[str] = None,
        target_format: Optional[str] = None,
        enable_ai: bool = True
    ) -> Dict[str, Any]:
        """
        Executes the entire 15-step recovery workflow and persists all results into PostgreSQL.
        """
        job_title = job_name or f"Recovery of {original_filename}"

        # 1. Create a recovery_job (status: pending)
        job = RecoveryJobRepository.create_job(
            db=self.db,
            job_name=job_title,
            user_id=user_id,
            status="pending",
            operation="recover_corrupted",
            source_type="uploaded_file",
            source_path=str(settings.input_dir / original_filename),
            target_filename=original_filename,
            target_type=target_format
        )

        # 15. Create audit_logs: JOB_CREATED
        AuditLogRepository.log_action(
            db=self.db,
            job_id=job.id,
            action="JOB_CREATED",
            details={
                "job_name": job.job_name,
                "filename": original_filename,
                "status": "pending"
            }
        )

        try:
            # 3. Calculate file hash
            file_hash = calculate_bytes_sha256(file_bytes)

            # Save uploaded raw bytes in existing physical file storage
            storage_path = settings.input_dir / f"{job.id}_{original_filename}"
            with open(storage_path, "wb") as f_in:
                f_in.write(file_bytes)

            # 4. Detect file type & MIME
            ext = Path(original_filename).suffix.lstrip(".").lower()
            detected_mime, detected_fmt = self.ai_svc.analyzer.detect_format(file_bytes)
            detected_type = detected_fmt or ext or "binary"
            mime_type = detected_mime or f"application/{detected_type}"

            # 2. Create a files record & 5. Store file metadata
            file_size = len(file_bytes)
            file_rec = FileRepository.create_file(
                db=self.db,
                job_id=job.id,
                original_name=original_filename,
                detected_type=detected_type,
                mime_type=mime_type,
                file_size=file_size,
                file_hash=file_hash,
                storage_path=str(storage_path.resolve()),
                damage_percentage=0.0,
                status="uploaded"
            )

            # 15. Audit: FILE_UPLOADED
            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="FILE_UPLOADED",
                details={
                    "file_id": str(file_rec.id),
                    "original_name": original_filename,
                    "file_size": file_size,
                    "file_hash": file_hash,
                    "detected_type": detected_type
                }
            )

            # 6. Start recovery processing (status: analyzing)
            RecoveryJobRepository.update_job_status(
                db=self.db,
                job_id=job.id,
                status="analyzing",
                current_stage="analyzing",
                progress=15
            )

            # 9. Run AI analysis
            analysis_res = self.ai_svc.analyzer.analyze(file_bytes, filename=original_filename)
            damage_pct = round(float(analysis_res.corruption_percentage), 1)
            file_rec.damage_percentage = damage_pct
            self.db.commit()

            # 15. Audit: FILE_ANALYZED
            structural_score = getattr(analysis_res, "structural_score", max(0.0, 100.0 - damage_pct))
            markers_present = getattr(analysis_res, "structural_markers_present", analysis_res.is_partially_readable)

            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="FILE_ANALYZED",
                details={
                    "corruption_detected": analysis_res.corruption_detected,
                    "corruption_percentage": damage_pct,
                    "structural_score": structural_score
                }
            )

            # 10. Save AI analysis to ai_analysis
            ai_conf = round(min(100.0, max(50.0 if detected_type not in ("unknown", "binary") else 0.0, float(structural_score))), 1)
            corr_type = "structural_marker_damage" if analysis_res.structural_repair_applied else (
                "bitstream_truncation" if damage_pct > 0 else "none"
            )
            ai_explanation = f"Detected {damage_pct}% visual and structural damage. Notes: {analysis_res.notes}"

            ai_rec = AIAnalysisRepository.create_or_update(
                db=self.db,
                file_id=file_rec.id,
                detected_file_type=detected_type.upper(),
                corruption_type=corr_type,
                confidence=ai_conf,
                model_name=settings.model_version,
                damaged_regions={"damage_percentage": damage_pct, "markers_present": markers_present},
                predicted_structure={"is_partially_readable": analysis_res.is_partially_readable, "notes": analysis_res.notes},
                explanation=ai_explanation
            )

            # 15. Audit: AI_ANALYSIS_COMPLETED
            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="AI_ANALYSIS_COMPLETED",
                details={
                    "analysis_id": str(ai_rec.id),
                    "confidence": ai_conf,
                    "corruption_type": corr_type
                }
            )

            # 7. Detect fragments (status: fragmenting)
            RecoveryJobRepository.update_job_status(
                db=self.db,
                job_id=job.id,
                status="fragmenting",
                current_stage="fragmenting",
                progress=40
            )

            frag_size = 4096
            raw_frags = slice_bytes_into_fragments(
                file_bytes,
                job_id=str(job.id),
                base_offset=0,
                fragment_size=frag_size,
                prefix_id="frag"
            )

            # 8. Save fragment metadata to fragments
            for idx, rf in enumerate(raw_frags, 1):
                pred = file_classifier.predict(rf.data)
                f_type = pred["predicted_type"]
                is_hdr = bool(rf.data.startswith(b"\xFF\xD8") or rf.data.startswith(b"\x89PNG") or rf.data.startswith(b"%PDF"))
                is_ftr = bool(b"\xFF\xD9" in rf.data[-4:] or b"IEND" in rf.data[-16:] or b"%%EOF" in rf.data[-32:])
                
                FragmentRepository.create_fragment(
                    db=self.db,
                    file_id=file_rec.id,
                    fragment_index=idx,
                    offset_start=rf.source_offset,
                    offset_end=rf.source_offset + rf.length,
                    fragment_size=rf.length,
                    fragment_hash=rf.sha256,
                    confidence=100.0 if rf.status == "valid" else 80.0,
                    is_valid=(rf.status == "valid"),
                    storage_path=None,
                    entropy=round(rf.entropy, 3),
                    predicted_type=f_type,
                    is_header=is_hdr,
                    is_footer=is_ftr
                )

            # 15. Audit: FRAGMENTS_DETECTED
            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="FRAGMENTS_DETECTED",
                details={"fragment_count": len(raw_frags), "chunk_size": frag_size}
            )

            # 11. Reconstruct the file (status: reconstructing)
            RecoveryJobRepository.update_job_status(
                db=self.db,
                job_id=job.id,
                status="reconstructing",
                current_stage="reconstructing",
                progress=65
            )

            # 15. Audit: RECONSTRUCTION_STARTED
            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="RECONSTRUCTION_STARTED",
                details={"target_format": detected_type}
            )

            # Perform recovery restoration
            rec_report = self.ai_svc.recover_image(
                file_bytes=file_bytes,
                filename=original_filename,
                enable_ai=enable_ai
            )

            # 12. Validate reconstructed file (status: validating)
            RecoveryJobRepository.update_job_status(
                db=self.db,
                job_id=job.id,
                status="validating",
                current_stage="validating",
                progress=85
            )

            recovered_path_str = rec_report.get("recoveredFilePath")
            if recovered_path_str and os.path.exists(recovered_path_str):
                with open(recovered_path_str, "rb") as rf_out:
                    rec_bytes = rf_out.read()
                out_hash = calculate_bytes_sha256(rec_bytes)
                rec_size = len(rec_bytes)
            else:
                from backend.services.file_repair_service import file_repair_service
                rep = file_repair_service.repair(
                    file_bytes,
                    filename=original_filename,
                    format_hint=target_format or detected_type
                )
                out_path = settings.output_dir / original_filename
                with open(out_path, "wb") as rf_out:
                    rf_out.write(rep.repaired_bytes)
                rec_bytes = rep.repaired_bytes
                out_hash = calculate_bytes_sha256(rec_bytes)
                rec_size = len(rec_bytes)
                recovered_path_str = str(out_path.resolve())
                rec_report["recoveredFilePath"] = recovered_path_str
                rec_report["recoveredFileName"] = original_filename
                rec_report["status"] = "success"
                rec_report["successRate"] = rep.integrity_score
                rec_report["success_rate"] = rep.integrity_score
                rec_report["validation"] = {
                    "is_valid": rep.is_valid,
                    "structural_score": rep.integrity_score
                }

            # 15. Audit: RECONSTRUCTION_COMPLETED
            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="RECONSTRUCTION_COMPLETED",
                details={"output_hash": out_hash, "recovered_size": rec_size}
            )

            val_dict = rec_report.get("validation", {"is_valid": True, "structural_score": 100.0})
            validation_status = "PASS" if val_dict.get("is_valid", True) else "PARTIAL"

            # 15. Audit: VALIDATION_COMPLETED
            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="VALIDATION_COMPLETED",
                details=val_dict
            )

            # 13. Save recovery information to recovery_results
            rec_pct = float(rec_report.get("successRate") or rec_report.get("success_rate") or (100.0 - damage_pct))
            rec_result = RecoveryResultRepository.create_result(
                db=self.db,
                file_id=file_rec.id,
                recovered_path=recovered_path_str,
                recovered_size=rec_size,
                recovery_percentage=rec_pct,
                validation_status=validation_status,
                output_hash=out_hash,
                validation_details=val_dict
            )

            # 14. Update recovery_jobs.status to completed or partial
            final_job_status = "completed" if rec_pct >= 90.0 else "partial"
            RecoveryJobRepository.update_job_status(
                db=self.db,
                job_id=job.id,
                status=final_job_status,
                current_stage="completed",
                progress=100
            )

            # 15. Audit: RECOVERY_COMPLETED
            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="RECOVERY_COMPLETED",
                details={
                    "status": final_job_status,
                    "recovery_percentage": rec_pct,
                    "result_id": str(rec_result.id)
                }
            )

            return {
                "id": str(job.id),
                "job_id": str(job.id),
                "status": final_job_status,
                "file": {
                    "name": original_filename,
                    "type": mime_type,
                    "size": file_size,
                    "damagePercentage": damage_pct
                },
                "fragments": {
                    "detected": len(raw_frags),
                    "valid": sum(1 for rf in raw_frags if rf.status == "valid"),
                    "reconstructed": len(raw_frags)
                },
                "aiAnalysis": {
                    "confidence": ai_conf,
                    "corruptionType": corr_type,
                    "explanation": ai_explanation
                },
                "recovery": {
                    "percentage": rec_pct,
                    "validationStatus": validation_status
                }
            }

        except Exception as e:
            logger.exception(f"Recovery failed for job {job.id}: {e}")
            RecoveryJobRepository.update_job_status(
                db=self.db,
                job_id=job.id,
                status="failed",
                current_stage="failed",
                error=str(e)
            )

            AuditLogRepository.log_action(
                db=self.db,
                job_id=job.id,
                action="RECOVERY_FAILED",
                details={"error": str(e)}
            )

            raise e

    def execute_recovery_workflow(
        self,
        source_path: str,
        original_filename: Optional[str] = None,
        job_name: Optional[str] = None,
        user_id: Optional[Any] = None,
        target_format: Optional[str] = None,
        enable_ai: bool = True
    ) -> Dict[str, Any]:
        """Convenience method to execute 15-step recovery workflow given a file path."""
        p = Path(source_path)
        with open(p, "rb") as f:
            file_bytes = f.read()
        fname = original_filename or p.name
        return self.process_file_recovery(
            file_bytes=file_bytes,
            original_filename=fname,
            user_id=user_id,
            job_name=job_name,
            target_format=target_format,
            enable_ai=enable_ai
        )
