"""
SQLAlchemy ORM models for recovery jobs, digital evidence sources, fragments, and reconstruction.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from backend.database.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class RecoveryJob(Base):
    __tablename__ = "recovery_jobs"

    id = Column(String(64), primary_key=True, index=True)
    operation = Column(String(64), nullable=False) # recover_corrupted, recover_deleted
    source_type = Column(String(64), nullable=False) # uploaded_file, disk_image, partition
    source_path = Column(String(512), nullable=False)
    target_filename = Column(String(256), nullable=True)
    target_type = Column(String(32), nullable=True) # jpeg, png, pdf, etc.
    status = Column(String(32), default="created", index=True) # created, acquiring, hashing, scanning, etc.
    current_stage = Column(String(64), default="created")
    progress = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    source = relationship("SourceAudit", back_populates="job", uselist=False, cascade="all, delete-orphan")
    fragments = relationship("FragmentRecord", back_populates="job", cascade="all, delete-orphan")
    candidates = relationship("ReconstructionCandidateRecord", back_populates="job", cascade="all, delete-orphan")
    recovered_files = relationship("RecoveredFileRecord", back_populates="job", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="job", cascade="all, delete-orphan")

class SourceAudit(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), ForeignKey("recovery_jobs.id"), nullable=False, index=True)
    source_path = Column(String(512), nullable=False)
    source_sha256 = Column(String(64), nullable=False)
    source_size = Column(Integer, nullable=False)
    source_type = Column(String(64), nullable=False)
    sector_size = Column(Integer, default=512)
    filesystem_detected = Column(String(32), default="unknown")
    acquired_at = Column(DateTime, default=utc_now)
    is_read_only = Column(Boolean, default=True)

    job = relationship("RecoveryJob", back_populates="source")

class FragmentRecord(Base):
    __tablename__ = "fragments"

    id = Column(String(64), primary_key=True, index=True) # e.g. FRAG-0001
    job_id = Column(String(64), ForeignKey("recovery_jobs.id"), nullable=False, index=True)
    source_offset = Column(Integer, nullable=False)
    length = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    predicted_type = Column(String(32), default="unknown")
    type_probabilities = Column(Text, nullable=True) # JSON dictionary
    entropy = Column(Float, default=0.0)
    status = Column(String(32), default="valid") # valid, corrupted, duplicate, unrelated, incomplete
    source_region = Column(String(64), default="unallocated")
    is_header = Column(Boolean, default=False)
    is_footer = Column(Boolean, default=False)
    creation_time = Column(DateTime, default=utc_now)

    job = relationship("RecoveryJob", back_populates="fragments")

class FragmentRelationshipRecord(Base):
    __tablename__ = "fragment_relationships"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), ForeignKey("recovery_jobs.id"), nullable=False, index=True)
    from_fragment_id = Column(String(64), nullable=False, index=True)
    to_fragment_id = Column(String(64), nullable=False, index=True)
    probability = Column(Float, nullable=False)
    model_version = Column(String(64), default="v1.0")
    relationship_type = Column(String(32), default="likely_successor")
    feature_metadata = Column(Text, nullable=True) # JSON evidence

class ReconstructionCandidateRecord(Base):
    __tablename__ = "reconstruction_candidates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), ForeignKey("recovery_jobs.id"), nullable=False, index=True)
    rank = Column(Integer, default=1)
    fragment_sequence = Column(Text, nullable=False) # JSON list of fragment IDs
    score = Column(Float, default=0.0)
    parser_valid = Column(Boolean, default=False)
    is_selected = Column(Boolean, default=False)
    evidence_details = Column(Text, nullable=True) # JSON details

    job = relationship("RecoveryJob", back_populates="candidates")

class RecoveredFileRecord(Base):
    __tablename__ = "recovered_files"

    id = Column(String(64), primary_key=True, index=True)
    job_id = Column(String(64), ForeignKey("recovery_jobs.id"), nullable=False, index=True)
    filename = Column(String(256), nullable=False)
    file_type = Column(String(32), nullable=False)
    output_path = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False)
    recovered_bytes = Column(Integer, default=0)
    missing_bytes = Column(Integer, default=0)
    fabricated_bytes = Column(Integer, default=0) # STRICTLY 0
    recoverability_score = Column(Float, default=0.0) # 0 to 100
    integrity_score = Column(Float, default=0.0) # 0 to 100
    model_confidence = Column(Float, default=0.0) # 0.0 to 1.0
    status = Column(String(32), default="recovered") # fully_recoverable, mostly_recoverable, partially_recoverable, etc.
    validation_details = Column(Text, nullable=True) # JSON details
    fragments_used = Column(Text, nullable=True) # JSON list of IDs
    missing_regions = Column(Text, nullable=True) # JSON list of missing regions
    created_at = Column(DateTime, default=utc_now)

    job = relationship("RecoveryJob", back_populates="recovered_files")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), ForeignKey("recovery_jobs.id"), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    details = Column(Text, nullable=True) # JSON details
    timestamp = Column(DateTime, default=utc_now)

    job = relationship("RecoveryJob", back_populates="audit_logs")
