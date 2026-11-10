"""
SQLAlchemy ORM models for PostgreSQL-backed Forensic Data Recovery System.

Database Schema:
1. users
   - id UUID PRIMARY KEY
   - name VARCHAR(255)
   - email VARCHAR(255) UNIQUE
   - created_at TIMESTAMPTZ

2. recovery_jobs
   - id UUID PRIMARY KEY
   - user_id UUID FK -> users.id
   - job_name VARCHAR(255)
   - status VARCHAR(32) (CHECK constraint: pending, analyzing, scanning, fragmenting, reconstructing, validating, completed, partial, failed)
   - started_at TIMESTAMPTZ
   - completed_at TIMESTAMPTZ
   - created_at TIMESTAMPTZ

3. files
   - id UUID PRIMARY KEY
   - job_id UUID FK -> recovery_jobs.id
   - original_name VARCHAR(255)
   - detected_type VARCHAR(64)
   - mime_type VARCHAR(128)
   - file_size BIGINT
   - file_hash VARCHAR(64)
   - storage_path VARCHAR(1024)
   - damage_percentage FLOAT (CHECK constraint: 0.0 - 100.0)
   - status VARCHAR(32)
   - created_at TIMESTAMPTZ

4. fragments
   - id UUID PRIMARY KEY
   - file_id UUID FK -> files.id
   - fragment_index INT
   - offset_start BIGINT
   - offset_end BIGINT
   - fragment_size INT
   - fragment_hash VARCHAR(64)
   - confidence FLOAT (CHECK constraint: 0.0 - 100.0)
   - is_valid BOOLEAN
   - storage_path VARCHAR(1024)
   - created_at TIMESTAMPTZ

5. ai_analysis
   - id UUID PRIMARY KEY
   - file_id UUID FK -> files.id (UNIQUE)
   - detected_file_type VARCHAR(64)
   - corruption_type VARCHAR(128)
   - damaged_regions JSONB/JSON
   - predicted_structure JSONB/JSON
   - confidence FLOAT (CHECK constraint: 0.0 - 100.0)
   - explanation TEXT
   - model_name VARCHAR(128)
   - created_at TIMESTAMPTZ

6. recovery_results
   - id UUID PRIMARY KEY
   - file_id UUID FK -> files.id
   - recovered_path VARCHAR(1024)
   - recovered_size BIGINT
   - recovery_percentage FLOAT (CHECK constraint: 0.0 - 100.0)
   - validation_status VARCHAR(64)
   - validation_details JSONB/JSON
   - output_hash VARCHAR(64)
   - created_at TIMESTAMPTZ

7. audit_logs
   - id BIGINT / BIGSERIAL PRIMARY KEY
   - job_id UUID FK -> recovery_jobs.id
   - action VARCHAR(64)
   - details JSONB/JSON
   - created_at TIMESTAMPTZ
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, Any

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text,
    ForeignKey, BigInteger, CheckConstraint, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator, CHAR, JSON
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB

from backend.database.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GUID(TypeDecorator):
    """
    Platform-independent GUID type.
    Uses PostgreSQL's native UUID type, otherwise uses CHAR(36) for SQLite / tests.
    Accepts both uuid.UUID and str transparently.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return str(value) if dialect.name != "postgresql" else value
        try:
            val_uuid = uuid.UUID(str(value))
            return val_uuid if dialect.name == "postgresql" else str(val_uuid)
        except (ValueError, AttributeError):
            return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            try:
                return uuid.UUID(str(value))
            except (ValueError, AttributeError):
                return value
        return value


# Cross-platform JSON type: JSONB on PostgreSQL, JSON on SQLite
JSON_TYPE = JSONB().with_variant(JSON(), "sqlite")


class User(Base):
    """Registered application user owning forensic data recovery jobs."""
    __tablename__ = "users"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    recovery_jobs = relationship("RecoveryJob", back_populates="user", cascade="all, delete-orphan")


class RecoveryJob(Base):
    """Forensic data recovery job coordinating multi-stage pipeline."""
    __tablename__ = "recovery_jobs"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    job_name = Column(String(255), nullable=False, default="Forensic Recovery Job")
    status = Column(
        String(32),
        CheckConstraint("status IN ('pending', 'created', 'in_progress', 'analyzing', 'scanning', 'fragmenting', 'reconstructing', 'validating', 'completed', 'partial', 'failed', 'cancelled')"),
        default="pending",
        nullable=False
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Operational pipeline metadata
    operation = Column(String(64), nullable=False, default="recover_corrupted")
    source_type = Column(String(64), nullable=False, default="uploaded_file")
    source_path = Column(String(512), nullable=False, default="")
    target_filename = Column(String(256), nullable=True)
    target_type = Column(String(32), nullable=True)
    current_stage = Column(String(64), default="created")
    progress = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    # Relationships
    user = relationship("User", back_populates="recovery_jobs")
    files = relationship("FileRecord", back_populates="job", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="job", cascade="all, delete-orphan")

    # Backward-compatible relations
    source = relationship("SourceAudit", back_populates="job", uselist=False, cascade="all, delete-orphan")
    legacy_fragments = relationship("LegacyFragmentRecord", back_populates="job", cascade="all, delete-orphan")
    candidates = relationship("ReconstructionCandidateRecord", back_populates="job", cascade="all, delete-orphan")
    recovered_files = relationship("RecoveredFileRecord", back_populates="job", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_recovery_jobs_user_id", "user_id"),
        Index("ix_recovery_jobs_status", "status"),
        Index("ix_recovery_jobs_created_at", "created_at"),
    )


class FileRecord(Base):
    """File evidence associated with a recovery job."""
    __tablename__ = "files"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    job_id = Column(GUID(), ForeignKey("recovery_jobs.id", ondelete="CASCADE"), nullable=False)
    original_name = Column(String(255), nullable=False)
    detected_type = Column(String(64), nullable=False)
    mime_type = Column(String(128), nullable=True)
    file_size = Column(BigInteger, nullable=False)
    file_hash = Column(String(64), nullable=False)
    storage_path = Column(String(1024), nullable=False)
    damage_percentage = Column(
        Float,
        CheckConstraint("damage_percentage >= 0.0 AND damage_percentage <= 100.0"),
        default=0.0,
        nullable=False
    )
    status = Column(String(32), default="uploaded", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    job = relationship("RecoveryJob", back_populates="files")
    fragments = relationship("FragmentRecord", back_populates="file", cascade="all, delete-orphan")
    ai_analysis = relationship("AIAnalysisRecord", back_populates="file", uselist=False, cascade="all, delete-orphan")
    recovery_results = relationship("RecoveryResultRecord", back_populates="file", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_files_job_id", "job_id"),
        Index("ix_files_file_hash", "file_hash"),
    )


class FragmentRecord(Base):
    """Binary fragment carved or extracted from evidence file."""
    __tablename__ = "fragments"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    file_id = Column(GUID(), ForeignKey("files.id", ondelete="CASCADE"), nullable=False)
    fragment_index = Column(Integer, nullable=False)
    offset_start = Column(BigInteger, nullable=False)
    offset_end = Column(BigInteger, nullable=False)
    fragment_size = Column(Integer, nullable=False)
    fragment_hash = Column(String(64), nullable=False)
    confidence = Column(
        Float,
        CheckConstraint("confidence >= 0.0 AND confidence <= 100.0"),
        default=100.0,
        nullable=False
    )
    is_valid = Column(Boolean, default=True, nullable=False)
    storage_path = Column(String(1024), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Forensic analytical details
    entropy = Column(Float, default=0.0)
    predicted_type = Column(String(32), default="unknown")
    is_header = Column(Boolean, default=False)
    is_footer = Column(Boolean, default=False)

    file = relationship("FileRecord", back_populates="fragments")

    __table_args__ = (
        Index("ix_fragments_file_id", "file_id"),
    )


class AIAnalysisRecord(Base):
    """AI and neural forensic model analysis on damaged file."""
    __tablename__ = "ai_analysis"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    file_id = Column(GUID(), ForeignKey("files.id", ondelete="CASCADE"), nullable=False, unique=True)
    detected_file_type = Column(String(64), nullable=False)
    corruption_type = Column(String(128), nullable=False)
    damaged_regions = Column(JSON_TYPE, nullable=True)
    predicted_structure = Column(JSON_TYPE, nullable=True)
    confidence = Column(
        Float,
        CheckConstraint("confidence >= 0.0 AND confidence <= 100.0"),
        default=0.0,
        nullable=False
    )
    explanation = Column(Text, nullable=True)
    model_name = Column(String(128), nullable=False, default="forensic-ai-v1")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    file = relationship("FileRecord", back_populates="ai_analysis")

    __table_args__ = (
        Index("ix_ai_analysis_file_id", "file_id"),
    )


class RecoveryResultRecord(Base):
    """Final recovery and reconstruction results."""
    __tablename__ = "recovery_results"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    file_id = Column(GUID(), ForeignKey("files.id", ondelete="CASCADE"), nullable=False)
    recovered_path = Column(String(1024), nullable=False)
    recovered_size = Column(BigInteger, default=0, nullable=False)
    recovery_percentage = Column(
        Float,
        CheckConstraint("recovery_percentage >= 0.0 AND recovery_percentage <= 100.0"),
        default=0.0,
        nullable=False
    )
    validation_status = Column(String(64), nullable=False, default="pending")
    validation_details = Column(JSON_TYPE, nullable=True)
    output_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    file = relationship("FileRecord", back_populates="recovery_results")

    __table_args__ = (
        Index("ix_recovery_results_file_id", "file_id"),
    )


class AuditLog(Base):
    """Immutable forensic audit ledger."""
    __tablename__ = "audit_logs"

    id = Column(BigInteger().with_variant(Integer(), "sqlite"), primary_key=True, autoincrement=True)
    job_id = Column(GUID(), ForeignKey("recovery_jobs.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(64), nullable=False)
    details = Column(JSON_TYPE, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    job = relationship("RecoveryJob", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_job_id", "job_id"),
    )


# -----------------------------------------------------------------------------
# Backward-Compatibility Auxiliary Models for Legacy Scans & Worker Operations
# -----------------------------------------------------------------------------
class SourceAudit(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(GUID(), ForeignKey("recovery_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    source_path = Column(String(512), nullable=False)
    source_sha256 = Column(String(64), nullable=False)
    source_size = Column(Integer, nullable=False)
    source_type = Column(String(64), nullable=False)
    sector_size = Column(Integer, default=512)
    filesystem_detected = Column(String(32), default="unknown")
    acquired_at = Column(DateTime(timezone=True), default=utc_now)
    is_read_only = Column(Boolean, default=True)

    job = relationship("RecoveryJob", back_populates="source")


class LegacyFragmentRecord(Base):
    __tablename__ = "legacy_fragments"

    id = Column(String(64), primary_key=True, index=True)
    job_id = Column(GUID(), ForeignKey("recovery_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    source_offset = Column(Integer, nullable=False)
    length = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    predicted_type = Column(String(32), default="unknown")
    type_probabilities = Column(Text, nullable=True)
    entropy = Column(Float, default=0.0)
    status = Column(String(32), default="valid")
    source_region = Column(String(64), default="unallocated")
    is_header = Column(Boolean, default=False)
    is_footer = Column(Boolean, default=False)
    creation_time = Column(DateTime(timezone=True), default=utc_now)

    job = relationship("RecoveryJob", back_populates="legacy_fragments")


class FragmentRelationshipRecord(Base):
    __tablename__ = "fragment_relationships"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(GUID(), ForeignKey("recovery_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    from_fragment_id = Column(String(64), nullable=False, index=True)
    to_fragment_id = Column(String(64), nullable=False, index=True)
    probability = Column(Float, nullable=False)
    model_version = Column(String(64), default="v1.0")
    relationship_type = Column(String(32), default="likely_successor")
    feature_metadata = Column(Text, nullable=True)


class ReconstructionCandidateRecord(Base):
    __tablename__ = "reconstruction_candidates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(GUID(), ForeignKey("recovery_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    rank = Column(Integer, default=1)
    fragment_sequence = Column(Text, nullable=False)
    score = Column(Float, default=0.0)
    parser_valid = Column(Boolean, default=False)
    is_selected = Column(Boolean, default=False)
    evidence_details = Column(Text, nullable=True)

    job = relationship("RecoveryJob", back_populates="candidates")


class RecoveredFileRecord(Base):
    __tablename__ = "recovered_files"

    id = Column(String(64), primary_key=True, index=True)
    job_id = Column(GUID(), ForeignKey("recovery_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(256), nullable=False)
    file_type = Column(String(32), nullable=False)
    output_path = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False)
    recovered_bytes = Column(Integer, default=0)
    missing_bytes = Column(Integer, default=0)
    fabricated_bytes = Column(Integer, default=0)
    recoverability_score = Column(Float, default=0.0)
    integrity_score = Column(Float, default=0.0)
    model_confidence = Column(Float, default=0.0)
    status = Column(String(32), default="recovered")
    validation_details = Column(Text, nullable=True)
    fragments_used = Column(Text, nullable=True)
    missing_regions = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    job = relationship("RecoveryJob", back_populates="recovered_files")
