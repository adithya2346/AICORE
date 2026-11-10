"""
Data access / repository layer for SQLite/PostgreSQL-backed Forensic Data Recovery System.
Encapsulates all database queries and transactions with parameterization and validation.
Supports both static and instance-based usage patterns.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc, asc, or_

from backend.database.models import (
    User, RecoveryJob, FileRecord, FragmentRecord,
    AIAnalysisRecord, RecoveryResultRecord, AuditLog
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserRepository:
    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def create(self, name: str, email: str) -> User:
        return self.create_user(self.db, name=name, email=email)

    @staticmethod
    def get_or_create_default_user(db: Session) -> User:
        """Retrieves or provisions the default local investigator user."""
        user = db.query(User).filter(User.email == "investigator@aegis.local").first()
        if not user:
            user = User(
                name="Forensic Investigator",
                email="investigator@aegis.local"
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return user

    @staticmethod
    def create_user(db: Session, name: str, email: str) -> User:
        user = User(name=name, email=email)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def get_by_id(db: Session, user_id: Any) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def get_by_email(db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()


class RecoveryJobRepository:
    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def create(self, **kwargs) -> RecoveryJob:
        return self.create_job(self.db, **kwargs)

    def get_by_id(self, job_id: Any) -> Optional[RecoveryJob]:
        return self.get_job_by_id(self.db, job_id)

    def update_status(self, job_id: Any, status: str, **kwargs) -> Optional[RecoveryJob]:
        return self.update_job_status(self.db, job_id=job_id, status=status, **kwargs)

    def get_all(self, page: int = 1, limit: int = 20, status_filter: Optional[str] = None, search: Optional[str] = None) -> Tuple[List[RecoveryJob], int]:
        res = self.list_jobs_models(self.db, page=page, limit=limit, status=status_filter, search=search)
        return res["items"], res["total"]

    def delete(self, job_id: Any) -> bool:
        job = self.db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
        if job:
            self.db.delete(job)
            self.db.commit()
            return True
        return False

    @staticmethod
    def create_job(
        db: Session,
        job_name: str,
        user_id: Optional[Any] = None,
        status: str = "pending",
        operation: str = "recover_corrupted",
        source_type: str = "uploaded_file",
        source_path: str = "",
        target_filename: Optional[str] = None,
        target_type: Optional[str] = None
    ) -> RecoveryJob:
        if not user_id:
            default_user = UserRepository.get_or_create_default_user(db)
            user_id = default_user.id

        job = RecoveryJob(
            user_id=user_id,
            job_name=job_name,
            status=status,
            started_at=utc_now() if status != "pending" else None,
            operation=operation,
            source_type=source_type,
            source_path=source_path,
            target_filename=target_filename,
            target_type=target_type,
            current_stage=status,
            progress=0
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    @staticmethod
    def get_job_by_id(db: Session, job_id: Any) -> Optional[RecoveryJob]:
        return db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()

    @staticmethod
    def update_job_status(
        db: Session,
        job_id: Any,
        status: str,
        stage: Optional[str] = None,
        current_stage: Optional[str] = None,
        progress: Optional[int] = None,
        error: Optional[str] = None
    ) -> Optional[RecoveryJob]:
        job = RecoveryJobRepository.get_job_by_id(db, job_id)
        if not job:
            return None

        effective_stage = stage or current_stage
        job.status = status
        if effective_stage:
            job.current_stage = effective_stage
        if progress is not None:
            job.progress = progress
        if error is not None:
            job.error = error

        if status in ("analyzing", "scanning", "fragmenting", "reconstructing", "validating") and not job.started_at:
            job.started_at = utc_now()
        elif status in ("completed", "partial", "failed"):
            job.completed_at = utc_now()

        db.commit()
        db.refresh(job)
        return job

    @staticmethod
    def list_jobs_models(
        db: Session,
        page: int = 1,
        limit: int = 20,
        status: Optional[str] = None,
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        query = db.query(RecoveryJob)
        if status:
            query = query.filter(RecoveryJob.status == status.lower())
        if search:
            term = f"%{search}%"
            query = query.outerjoin(FileRecord).filter(
                or_(
                    RecoveryJob.job_name.ilike(term),
                    FileRecord.original_name.ilike(term),
                    RecoveryJob.status.ilike(term)
                )
            )
        total = query.count()
        offset = max(0, (page - 1) * limit)
        items = query.order_by(desc(RecoveryJob.created_at)).offset(offset).limit(limit).all()
        return {"items": items, "total": total}

    @staticmethod
    def list_jobs(
        db: Session,
        page: int = 1,
        limit: int = 20,
        status: Optional[str] = None,
        file_type: Optional[str] = None,
        search: Optional[str] = None,
        sort: str = "created_at",
        order: str = "desc"
    ) -> Dict[str, Any]:
        """Paginated, searchable, and filtered recovery jobs listing."""
        query = db.query(RecoveryJob)

        if status:
            query = query.filter(RecoveryJob.status == status.lower())

        if file_type:
            query = query.join(FileRecord).filter(FileRecord.detected_type.ilike(f"%{file_type}%"))

        if search:
            search_term = f"%{search}%"
            query = query.outerjoin(FileRecord).filter(
                or_(
                    RecoveryJob.job_name.ilike(search_term),
                    FileRecord.original_name.ilike(search_term),
                    RecoveryJob.status.ilike(search_term)
                )
            )

        total = query.count()

        # Sorting
        sort_col = getattr(RecoveryJob, sort, RecoveryJob.created_at)
        if order.lower() == "asc":
            query = query.order_by(asc(sort_col))
        else:
            query = query.order_by(desc(sort_col))

        offset = max(0, (page - 1) * limit)
        items = query.offset(offset).limit(limit).all()

        formatted_items = []
        for j in items:
            f = j.files[0] if j.files else None
            res = f.recovery_results[0] if f and f.recovery_results else None
            ai = f.ai_analysis if f else None

            formatted_items.append({
                "job_id": str(j.id),
                "id": str(j.id),
                "job_name": j.job_name,
                "status": j.status,
                "current_stage": j.current_stage,
                "progress": j.progress,
                "operation": j.operation,
                "created_at": j.created_at.isoformat() if j.created_at else None,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
                "file": {
                    "name": f.original_name if f else j.target_filename or "Unknown",
                    "type": f.detected_type if f else j.target_type or "unknown",
                    "size": f.file_size if f else 0,
                    "damage_percentage": f.damage_percentage if f else 0.0
                } if f else None,
                "recovery_percentage": res.recovery_percentage if res else (100.0 if j.status == "completed" else 0.0),
                "ai_confidence": ai.confidence if ai else 0.0
            })

        return {
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if limit > 0 else 1,
            "items": formatted_items
        }

    @staticmethod
    def get_dashboard_stats(db: Session) -> Dict[str, Any]:
        """Aggregates real statistics straight from persistent database."""
        total_jobs = db.query(func.count(RecoveryJob.id)).scalar() or 0
        active_jobs = db.query(func.count(RecoveryJob.id)).filter(
            RecoveryJob.status.in_(["pending", "analyzing", "scanning", "fragmenting", "reconstructing", "validating"])
        ).scalar() or 0
        completed_recoveries = db.query(func.count(RecoveryJob.id)).filter(
            RecoveryJob.status == "completed"
        ).scalar() or 0
        failed_recoveries = db.query(func.count(RecoveryJob.id)).filter(
            RecoveryJob.status == "failed"
        ).scalar() or 0

        # Average recovery percentage from real recovery_results records
        avg_rec = db.query(func.avg(RecoveryResultRecord.recovery_percentage)).scalar()
        if avg_rec is None:
            avg_rec = 100.0 if completed_recoveries > 0 else 0.0

        # File type distribution
        type_rows = db.query(
            FileRecord.detected_type, func.count(FileRecord.id)
        ).group_by(FileRecord.detected_type).all()
        type_dist = {r[0].upper(): r[1] for r in type_rows if r[0]}

        # Recovery status distribution
        status_rows = db.query(
            RecoveryJob.status, func.count(RecoveryJob.id)
        ).group_by(RecoveryJob.status).all()
        status_dist = {r[0]: r[1] for r in status_rows if r[0]}

        # AI Confidence average
        avg_conf = db.query(func.avg(AIAnalysisRecord.confidence)).scalar() or 0.0

        # Fragments metrics
        tot_frags = db.query(func.count(FragmentRecord.id)).scalar() or 0
        valid_frags = db.query(func.count(FragmentRecord.id)).filter(FragmentRecord.is_valid == True).scalar() or 0

        # Recent 5 jobs
        recent_records = db.query(RecoveryJob).order_by(desc(RecoveryJob.created_at)).limit(5).all()
        recent_list = []
        for rj in recent_records:
            f = rj.files[0] if rj.files else None
            recent_list.append({
                "job_id": str(rj.id),
                "job_name": rj.job_name,
                "status": rj.status,
                "file_name": f.original_name if f else rj.target_filename or "evidence.bin",
                "file_type": f.detected_type if f else rj.target_type or "unknown",
                "created_at": rj.created_at.isoformat() if rj.created_at else None
            })

        return {
            "total_jobs": total_jobs,
            "active_jobs": active_jobs,
            "completed_recoveries": completed_recoveries,
            "failed_recoveries": failed_recoveries,
            "average_recovery_percentage": round(float(avg_rec), 1),
            "recent_jobs": recent_list,
            "file_type_distribution": type_dist,
            "recovery_status_distribution": status_dist,
            "average_ai_confidence": round(float(avg_conf), 1),
            "fragment_information": {
                "total_detected": tot_frags,
                "valid": valid_frags,
                "invalid": max(0, tot_frags - valid_frags)
            }
        }


class FileRepository:
    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def create(self, job_id: Any, original_name: str, detected_type: str, file_size: int, file_hash: str, storage_path: str, damage_percentage: float = 0.0, mime_type: Optional[str] = None, status: str = "uploaded") -> FileRecord:
        return self.create_file(
            db=self.db,
            job_id=job_id,
            original_name=original_name,
            detected_type=detected_type,
            file_size=file_size,
            file_hash=file_hash,
            storage_path=storage_path,
            damage_percentage=damage_percentage,
            mime_type=mime_type,
            status=status
        )

    def get_by_hash(self, file_hash: str) -> List[FileRecord]:
        return self.db.query(FileRecord).filter(FileRecord.file_hash == file_hash).all()

    @staticmethod
    def create_file(
        db: Session,
        job_id: Any,
        original_name: str,
        detected_type: str,
        file_size: int,
        file_hash: str,
        storage_path: str,
        damage_percentage: float = 0.0,
        mime_type: Optional[str] = None,
        status: str = "uploaded"
    ) -> FileRecord:
        clamped_damage = max(0.0, min(100.0, float(damage_percentage)))
        file_rec = FileRecord(
            job_id=job_id,
            original_name=original_name,
            detected_type=detected_type,
            mime_type=mime_type,
            file_size=file_size,
            file_hash=file_hash,
            storage_path=storage_path,
            damage_percentage=clamped_damage,
            status=status
        )
        db.add(file_rec)
        db.commit()
        db.refresh(file_rec)
        return file_rec

    @staticmethod
    def get_by_id(db: Session, file_id: Any) -> Optional[FileRecord]:
        return db.query(FileRecord).filter(FileRecord.id == file_id).first()

    @staticmethod
    def get_by_job(db: Session, job_id: Any) -> List[FileRecord]:
        return db.query(FileRecord).filter(FileRecord.job_id == job_id).all()


class FragmentRepository:
    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def create_many(self, file_id: Any, fragments: List[Dict[str, Any]]) -> List[FragmentRecord]:
        created = []
        for f in fragments:
            rec = self.create_fragment(
                db=self.db,
                file_id=file_id,
                fragment_index=f.get("fragment_index", 0),
                offset_start=f.get("offset_start", 0),
                offset_end=f.get("offset_end", 0),
                fragment_size=f.get("fragment_size", 0),
                fragment_hash=f.get("fragment_hash", ""),
                confidence=f.get("confidence", 100.0),
                is_valid=f.get("is_valid", True),
                storage_path=f.get("storage_path"),
                entropy=f.get("entropy", 0.0),
                predicted_type=f.get("predicted_type", "unknown"),
                is_header=f.get("is_header", False),
                is_footer=f.get("is_footer", False)
            )
            created.append(rec)
        return created

    def get_by_file(self, file_id: Any) -> List[FragmentRecord]:
        return self.get_fragments_by_file(self.db, file_id)

    @staticmethod
    def create_fragment(
        db: Session,
        file_id: Any,
        fragment_index: int,
        offset_start: int,
        offset_end: int,
        fragment_size: int,
        fragment_hash: str,
        confidence: float = 100.0,
        is_valid: bool = True,
        storage_path: Optional[str] = None,
        entropy: float = 0.0,
        predicted_type: str = "unknown",
        is_header: bool = False,
        is_footer: bool = False
    ) -> FragmentRecord:
        clamped_conf = max(0.0, min(100.0, float(confidence)))
        frag = FragmentRecord(
            file_id=file_id,
            fragment_index=fragment_index,
            offset_start=offset_start,
            offset_end=offset_end,
            fragment_size=fragment_size,
            fragment_hash=fragment_hash,
            confidence=clamped_conf,
            is_valid=is_valid,
            storage_path=storage_path,
            entropy=entropy,
            predicted_type=predicted_type,
            is_header=is_header,
            is_footer=is_footer
        )
        db.add(frag)
        db.commit()
        db.refresh(frag)
        return frag

    @staticmethod
    def get_fragments_by_file(db: Session, file_id: Any) -> List[FragmentRecord]:
        return db.query(FragmentRecord).filter(
            FragmentRecord.file_id == file_id
        ).order_by(FragmentRecord.fragment_index.asc()).all()


class AIAnalysisRepository:
    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def create(self, **kwargs) -> AIAnalysisRecord:
        return self.create_or_update(self.db, **kwargs)

    def get_by_file(self, file_id: Any) -> Optional[AIAnalysisRecord]:
        return self.get_analysis_by_file(self.db, file_id)

    @staticmethod
    def create_or_update(
        db: Session,
        file_id: Any,
        detected_file_type: str,
        corruption_type: str,
        confidence: float,
        model_name: str = "forensic-ai-v1",
        damaged_regions: Optional[Any] = None,
        predicted_structure: Optional[Any] = None,
        explanation: Optional[str] = None
    ) -> AIAnalysisRecord:
        clamped_conf = max(0.0, min(100.0, float(confidence)))
        analysis = db.query(AIAnalysisRecord).filter(AIAnalysisRecord.file_id == file_id).first()
        if not analysis:
            analysis = AIAnalysisRecord(
                file_id=file_id,
                detected_file_type=detected_file_type,
                corruption_type=corruption_type,
                confidence=clamped_conf,
                model_name=model_name,
                damaged_regions=damaged_regions,
                predicted_structure=predicted_structure,
                explanation=explanation
            )
            db.add(analysis)
        else:
            analysis.detected_file_type = detected_file_type
            analysis.corruption_type = corruption_type
            analysis.confidence = clamped_conf
            analysis.model_name = model_name
            analysis.damaged_regions = damaged_regions
            analysis.predicted_structure = predicted_structure
            analysis.explanation = explanation

        db.commit()
        db.refresh(analysis)
        return analysis

    @staticmethod
    def get_analysis_by_file(db: Session, file_id: Any) -> Optional[AIAnalysisRecord]:
        return db.query(AIAnalysisRecord).filter(AIAnalysisRecord.file_id == file_id).first()


class RecoveryResultRepository:
    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def create(self, **kwargs) -> RecoveryResultRecord:
        return self.create_result(self.db, **kwargs)

    def get_by_file(self, file_id: Any) -> Optional[RecoveryResultRecord]:
        return self.get_result_by_file(self.db, file_id)

    @staticmethod
    def create_result(
        db: Session,
        file_id: Any,
        recovered_path: str,
        recovered_size: int,
        recovery_percentage: float,
        validation_status: str,
        output_hash: str,
        validation_details: Optional[Any] = None
    ) -> RecoveryResultRecord:
        clamped_rec = max(0.0, min(100.0, float(recovery_percentage)))
        res = RecoveryResultRecord(
            file_id=file_id,
            recovered_path=recovered_path,
            recovered_size=recovered_size,
            recovery_percentage=clamped_rec,
            validation_status=validation_status,
            validation_details=validation_details,
            output_hash=output_hash
        )
        db.add(res)
        db.commit()
        db.refresh(res)
        return res

    @staticmethod
    def get_result_by_file(db: Session, file_id: Any) -> Optional[RecoveryResultRecord]:
        return db.query(RecoveryResultRecord).filter(RecoveryResultRecord.file_id == file_id).first()


class _LogMethodDescriptor:
    def __get__(self, instance, owner):
        def _log(*args, **kwargs):
            db = kwargs.pop("db", getattr(instance, "db", None))
            if db is None and len(args) > 0 and (isinstance(args[0], Session) or hasattr(args[0], "execute")):
                db = args[0]
                args = args[1:]
            job_id = kwargs.pop("job_id", args[0] if len(args) > 0 else None)
            action = kwargs.pop("action", args[1] if len(args) > 1 else None)
            details = kwargs.pop("details", args[2] if len(args) > 2 else None)
            return owner.log_action(db=db, job_id=job_id, action=action, details=details)
        return _log


class AuditLogRepository:
    def __init__(self, db: Optional[Session] = None):
        self.db = db

    log = _LogMethodDescriptor()

    def get_by_job(self, job_id: Any) -> List[AuditLog]:
        return self.get_audit_by_job(self.db, job_id)

    @staticmethod
    def log_action(db: Session, job_id: Any, action: str, details: Optional[Any] = None) -> AuditLog:
        audit = AuditLog(
            job_id=job_id,
            action=action,
            details=details
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)
        return audit

    @staticmethod
    def get_audit_by_job(db: Session, job_id: Any) -> List[AuditLog]:
        return db.query(AuditLog).filter(
            AuditLog.job_id == job_id
        ).order_by(AuditLog.created_at.asc()).all()
