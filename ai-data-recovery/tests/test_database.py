"""
Comprehensive Database Unit and Integration Tests for Forensic Data Recovery.

Tests:
1. Creating a recovery job
2. Uploading file metadata
3. Storing fragments
4. Storing AI analysis
5. Storing recovery results
6. Retrieving recovery history (pagination, search, filter)
7. Updating recovery status
8. Deleting/cascading related records
9. Invalid percentage values (CHECK constraints: 0-100)
10. Handling duplicate file hashes
11. Complete 15-step recovery workflow
"""
import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from backend.database.models import (
    Base, User, RecoveryJob, FileRecord, FragmentRecord,
    AIAnalysisRecord, RecoveryResultRecord, AuditLog
)
from backend.database.repository import (
    UserRepository, RecoveryJobRepository, FileRepository,
    FragmentRepository, AIAnalysisRepository, RecoveryResultRepository,
    AuditLogRepository
)
from backend.services.recovery_service import DatabaseRecoveryWorkflow


@pytest.fixture(scope="function")
def test_db():
    """Create an isolated in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_create_recovery_job(test_db):
    """Test creating a recovery job with user association."""
    user_repo = UserRepository(test_db)
    job_repo = RecoveryJobRepository(test_db)

    user = user_repo.create(name="Special Agent", email="agent@forensics.gov")
    assert user.id is not None
    assert user.email == "agent@forensics.gov"

    job = job_repo.create(
        user_id=user.id,
        job_name="Operation Goldeneye",
        operation="recover_corrupted",
        source_path="corrupted.bin"
    )
    assert job.id is not None
    assert job.status == "pending"
    assert job.job_name == "Operation Goldeneye"
    assert job.user_id == user.id


def test_upload_file_metadata(test_db):
    """Test creating and persisting file evidence metadata."""
    job_repo = RecoveryJobRepository(test_db)
    file_repo = FileRepository(test_db)

    job = job_repo.create(job_name="File Evidence Test")
    file_rec = file_repo.create(
        job_id=job.id,
        original_name="evidence_disk.img",
        detected_type="raw_image",
        mime_type="application/octet-stream",
        file_size=1048576,
        file_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        storage_path="workspace/input/evidence_disk.img",
        damage_percentage=15.5
    )

    assert file_rec.id is not None
    assert file_rec.job_id == job.id
    assert file_rec.file_size == 1048576
    assert file_rec.damage_percentage == 15.5


def test_store_fragments(test_db):
    """Test storing carved fragments linked to a file record."""
    job_repo = RecoveryJobRepository(test_db)
    file_repo = FileRepository(test_db)
    frag_repo = FragmentRepository(test_db)

    job = job_repo.create(job_name="Carve Fragments")
    file_rec = file_repo.create(
        job_id=job.id,
        original_name="drive.dd",
        detected_type="dd",
        file_size=4096,
        file_hash="hash000000000000000000000000000000000000000000000000000000000000",
        storage_path="path/to/drive.dd"
    )

    fragments_data = [
        {
            "fragment_index": 0,
            "offset_start": 0,
            "offset_end": 2048,
            "fragment_size": 2048,
            "fragment_hash": "frag_hash_0",
            "confidence": 98.5,
            "is_valid": True,
            "entropy": 7.4,
            "predicted_type": "jpeg",
            "is_header": True,
            "is_footer": False
        },
        {
            "fragment_index": 1,
            "offset_start": 2048,
            "offset_end": 4096,
            "fragment_size": 2048,
            "fragment_hash": "frag_hash_1",
            "confidence": 94.0,
            "is_valid": True,
            "entropy": 6.8,
            "predicted_type": "jpeg",
            "is_header": False,
            "is_footer": True
        }
    ]

    saved_frags = frag_repo.create_many(file_rec.id, fragments_data)
    assert len(saved_frags) == 2
    assert saved_frags[0].is_header is True
    assert saved_frags[1].is_footer is True

    fetched = frag_repo.get_by_file(file_rec.id)
    assert len(fetched) == 2


def test_store_ai_analysis(test_db):
    """Test storing AI forensic analysis results."""
    job_repo = RecoveryJobRepository(test_db)
    file_repo = FileRepository(test_db)
    ai_repo = AIAnalysisRepository(test_db)

    job = job_repo.create(job_name="AI Analysis Job")
    file_rec = file_repo.create(
        job_id=job.id,
        original_name="damaged.png",
        detected_type="image/png",
        file_size=2048,
        file_hash="pnghash123",
        storage_path="path/to/damaged.png"
    )

    ai_record = ai_repo.create(
        file_id=file_rec.id,
        detected_file_type="image/png",
        corruption_type="ihdr_checksum_mismatch",
        damaged_regions=[{"offset": 12, "length": 4, "type": "CRC"}],
        predicted_structure={"chunks": ["IHDR", "IDAT", "IEND"]},
        confidence=92.5,
        explanation="IHDR CRC mismatch corrected based on PNG bitstream structure.",
        model_name="forensic-neural-carver-v1"
    )

    assert ai_record.id is not None
    assert ai_record.confidence == 92.5
    assert ai_record.corruption_type == "ihdr_checksum_mismatch"
    assert ai_record.file_id == file_rec.id


def test_store_recovery_results(test_db):
    """Test storing final file reconstruction and validation results."""
    job_repo = RecoveryJobRepository(test_db)
    file_repo = FileRepository(test_db)
    result_repo = RecoveryResultRepository(test_db)

    job = job_repo.create(job_name="Reconstruct Job")
    file_rec = file_repo.create(
        job_id=job.id,
        original_name="corrupt.jpg",
        detected_type="image/jpeg",
        file_size=50000,
        file_hash="hashinput",
        storage_path="path/input"
    )

    result = result_repo.create(
        file_id=file_rec.id,
        recovered_path="recovery_workspace/output/recovered.jpg",
        recovered_size=49800,
        recovery_percentage=99.6,
        validation_status="PASS",
        validation_details={"magic_bytes_valid": True, "pixel_decode": "OK"},
        output_hash="hashoutput"
    )

    assert result.id is not None
    assert result.recovery_percentage == 99.6
    assert result.validation_status == "PASS"
    assert result.output_hash == "hashoutput"


def test_retrieve_recovery_history_and_filters(test_db):
    """Test querying jobs with pagination, status filters, and search."""
    job_repo = RecoveryJobRepository(test_db)

    job1 = job_repo.create(job_name="Suspicious USB Recovery", operation="recover_corrupted")
    job_repo.update_status(job1.id, "completed")

    job2 = job_repo.create(job_name="Deleted Phone Photos", operation="scan_deleted")
    job_repo.update_status(job2.id, "failed")

    job3 = job_repo.create(job_name="Corrupt SD Card", operation="recover_corrupted")
    job_repo.update_status(job3.id, "reconstructing")

    # 1. Total count
    items, total = job_repo.get_all(page=1, limit=10)
    assert total == 3

    # 2. Filter by status
    completed_items, c_total = job_repo.get_all(page=1, limit=10, status_filter="completed")
    assert c_total == 1
    assert completed_items[0].job_name == "Suspicious USB Recovery"

    # 3. Search query
    search_items, s_total = job_repo.get_all(page=1, limit=10, search="Phone")
    assert s_total == 1
    assert search_items[0].job_name == "Deleted Phone Photos"

    # 4. Pagination
    p_items, p_total = job_repo.get_all(page=2, limit=2)
    assert p_total == 3
    assert len(p_items) == 1


def test_update_recovery_status(test_db):
    """Test transitioning recovery job statuses through pipeline stages."""
    job_repo = RecoveryJobRepository(test_db)
    job = job_repo.create(job_name="Status Pipeline Test")

    valid_statuses = [
        "analyzing", "scanning", "fragmenting",
        "reconstructing", "validating", "completed"
    ]

    for st in valid_statuses:
        updated = job_repo.update_status(job.id, st, progress=50, stage=st)
        assert updated.status == st
        assert updated.current_stage == st

    # When completed, completed_at should be populated
    final_job = job_repo.get_by_id(job.id)
    assert final_job.completed_at is not None


def test_cascade_delete(test_db):
    """Test cascading deletion from recovery job down to files, fragments, and results."""
    job_repo = RecoveryJobRepository(test_db)
    file_repo = FileRepository(test_db)
    frag_repo = FragmentRepository(test_db)
    audit_repo = AuditLogRepository(test_db)

    job = job_repo.create(job_name="Job to be Deleted")
    file_rec = file_repo.create(
        job_id=job.id,
        original_name="target.bin",
        detected_type="bin",
        file_size=1024,
        file_hash="hash123",
        storage_path="path"
    )
    frag_repo.create_many(file_rec.id, [{
        "fragment_index": 0, "offset_start": 0, "offset_end": 512,
        "fragment_size": 512, "fragment_hash": "fhash", "confidence": 100.0, "is_valid": True
    }])
    audit_repo.log(job.id, "JOB_CREATED", {"info": "test"})

    # Verify records exist
    assert test_db.query(FileRecord).filter(FileRecord.job_id == job.id).count() == 1
    assert test_db.query(FragmentRecord).filter(FragmentRecord.file_id == file_rec.id).count() == 1
    assert test_db.query(AuditLog).filter(AuditLog.job_id == job.id).count() == 1

    # Delete job
    deleted = job_repo.delete(job.id)
    assert deleted is True

    # Check cascading deletes
    assert test_db.query(FileRecord).filter(FileRecord.job_id == job.id).count() == 0
    assert test_db.query(FragmentRecord).filter(FragmentRecord.file_id == file_rec.id).count() == 0
    assert test_db.query(AuditLog).filter(AuditLog.job_id == job.id).count() == 0


def test_check_constraints_percentage_limits(test_db):
    """Test CHECK constraint enforcing percentage between 0.0 and 100.0."""
    job = RecoveryJob(id=uuid.uuid4(), job_name="Constraint Check", status="pending")
    test_db.add(job)
    test_db.commit()

    # Invalid damage_percentage (> 100)
    invalid_file = FileRecord(
        id=uuid.uuid4(),
        job_id=job.id,
        original_name="invalid.bin",
        detected_type="bin",
        file_size=100,
        file_hash="hash",
        storage_path="path",
        damage_percentage=150.0  # VIOLATION
    )
    test_db.add(invalid_file)
    with pytest.raises(IntegrityError):
        test_db.commit()
    test_db.rollback()

    # Invalid damage_percentage (< 0)
    negative_file = FileRecord(
        id=uuid.uuid4(),
        job_id=job.id,
        original_name="negative.bin",
        detected_type="bin",
        file_size=100,
        file_hash="hash",
        storage_path="path",
        damage_percentage=-5.0  # VIOLATION
    )
    test_db.add(negative_file)
    with pytest.raises(IntegrityError):
        test_db.commit()
    test_db.rollback()


def test_duplicate_file_hashes(test_db):
    """Test that multiple files can have identical hashes (e.g. repeated scans of same file)."""
    job_repo = RecoveryJobRepository(test_db)
    file_repo = FileRepository(test_db)

    job1 = job_repo.create(job_name="Scan 1")
    job2 = job_repo.create(job_name="Scan 2")

    same_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    f1 = file_repo.create(job1.id, "photo.jpg", "image/jpeg", 1000, same_hash, "path1")
    f2 = file_repo.create(job2.id, "copy.jpg", "image/jpeg", 1000, same_hash, "path2")

    assert f1.file_hash == f2.file_hash
    files_with_hash = file_repo.get_by_hash(same_hash)
    assert len(files_with_hash) == 2


def test_complete_15_step_recovery_workflow(test_db, tmp_path):
    """
    Test the full 15-step recovery workflow end-to-end:
    1. Create recovery_job
    2. Create files record
    3. Calculate file hash
    4. Detect file type
    5. Store file metadata
    6. Start recovery processing
    7. Detect fragments
    8. Save fragment metadata to fragments
    9. Run AI analysis
    10. Save AI analysis to ai_analysis
    11. Reconstruct the file
    12. Validate the reconstructed file
    13. Save recovery information to recovery_results
    14. Update recovery_jobs.status
    15. Create audit_logs for important operations
    """
    # Create sample evidence file (valid JPEG structure)
    evidence_content = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00ForensicEvidenceSampleDataBlock\xFF\xD9"
    test_file_path = tmp_path / "test_evidence.jpg"
    test_file_path.write_bytes(evidence_content)

    workflow = DatabaseRecoveryWorkflow(test_db)
    result = workflow.execute_recovery_workflow(
        source_path=str(test_file_path),
        original_filename="test_evidence.jpg",
        job_name="End-to-End Forensic Workflow Test"
    )

    assert result["status"] == "completed"
    assert "job_id" in result
    assert "file" in result
    assert "fragments" in result
    assert "aiAnalysis" in result
    assert "recovery" in result

    # Verify recovery result details
    assert result["file"]["name"] == "test_evidence.jpg"
    assert result["file"]["type"] == "image/jpeg"
    assert result["fragments"]["detected"] >= 1
    assert result["aiAnalysis"]["confidence"] > 0
    assert result["recovery"]["validationStatus"] == "PASS"

    # Verify audit logs in database
    job_id = result["job_id"]
    audit_logs = test_db.query(AuditLog).filter(AuditLog.job_id == job_id).all()
    actions = [log.action for log in audit_logs]
    
    assert "JOB_CREATED" in actions
    assert "FILE_UPLOADED" in actions
    assert "FILE_ANALYZED" in actions
    assert "FRAGMENTS_DETECTED" in actions
    assert "AI_ANALYSIS_COMPLETED" in actions
    assert "RECONSTRUCTION_STARTED" in actions
    assert "RECONSTRUCTION_COMPLETED" in actions
    assert "VALIDATION_COMPLETED" in actions
    assert "RECOVERY_COMPLETED" in actions
