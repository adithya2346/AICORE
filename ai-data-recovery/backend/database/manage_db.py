"""
Database Management CLI for AI-Assisted Data Recovery System.

Usage:
    python -m backend.database.manage_db migrate
    python -m backend.database.manage_db reset
    python -m backend.database.manage_db seed
    python -m backend.database.manage_db check
    python -m backend.database.manage_db status
"""
import sys
import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.config import settings
from backend.database.database import engine, SessionLocal, check_db_connection, Base
from backend.database.models import (
    User, RecoveryJob, FileRecord, FragmentRecord,
    AIAnalysisRecord, RecoveryResultRecord, AuditLog
)
from sqlalchemy import text


def run_migrations():
    """Run database migrations or synchronize schema."""
    if engine.dialect.name == "sqlite":
        print(f"[*] Synchronizing SQLite schema for {settings.database_url}...")
        Base.metadata.create_all(bind=engine)
        print("[+] All SQLite tables and indexes verified/created successfully.")
        return

    print(f"[*] Applying migrations to database: {settings.db_name} at {settings.db_host}:{settings.db_port}...")
    try:
        from alembic.config import Config
        from alembic import command
        
        ini_path = Path(__file__).resolve().parent.parent.parent / "alembic.ini"
        alembic_cfg = Config(str(ini_path))
        command.upgrade(alembic_cfg, "head")
        print("[+] Migrations applied successfully via Alembic.")
    except Exception as e:
        print(f"[!] Alembic execution notice: {e}")
        print("[*] Creating all schema tables via SQLAlchemy ORM metadata...")
        Base.metadata.create_all(bind=engine)
        print("[+] All tables created successfully.")


def reset_database():
    """Drop all tables and recreate them."""
    print(f"[!] RESETTING DATABASE: {settings.db_name}...")
    try:
        Base.metadata.drop_all(bind=engine)
        print("[+] All tables dropped.")
    except Exception as e:
        print(f"[!] Warning dropping tables: {e}")
    
    run_migrations()
    print("[+] Database reset and schema initialized.")


def seed_database():
    """Seed sample data for development and testing."""
    print("[*] Seeding database with initial developer records...")
    db = SessionLocal()
    try:
        # Check or create default forensic user
        user = db.query(User).filter(User.email == "analyst@forensics.local").first()
        if not user:
            user = User(
                id=uuid.uuid4(),
                name="Forensic Analyst",
                email="analyst@forensics.local",
                created_at=datetime.now(timezone.utc)
            )
            db.add(user)
            db.flush()
            print(f"[+] Created default user: {user.email} (ID: {user.id})")
        else:
            print(f"[*] Using existing user: {user.email}")

        # Seed sample completed recovery job
        job_id = uuid.uuid4()
        job = RecoveryJob(
            id=job_id,
            user_id=user.id,
            job_name="Damaged Evidence Photo Recovery",
            status="completed",
            operation="recover_corrupted",
            source_type="uploaded_file",
            source_path="damaged_photo.jpg",
            target_filename="damaged_photo.jpg",
            target_type="jpg",
            current_stage="completed",
            progress=100,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc)
        )
        db.add(job)
        db.flush()

        # Seed file record
        file_id = uuid.uuid4()
        file_rec = FileRecord(
            id=file_id,
            job_id=job.id,
            original_name="damaged_photo.jpg",
            detected_type="image/jpeg",
            mime_type="image/jpeg",
            file_size=4200000,
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            storage_path=f"recovery_workspace/input/{file_id}_damaged_photo.jpg",
            damage_percentage=18.0,
            status="recovered",
            created_at=datetime.now(timezone.utc)
        )
        db.add(file_rec)
        db.flush()

        # Seed fragment records
        for i in range(3):
            frag = FragmentRecord(
                id=uuid.uuid4(),
                file_id=file_rec.id,
                fragment_index=i,
                offset_start=i * 1400000,
                offset_end=(i + 1) * 1400000,
                fragment_size=1400000,
                fragment_hash=f"hash_fragment_{i}_{job_id.hex[:8]}",
                confidence=95.0 - (i * 2.0),
                is_valid=True,
                storage_path=f"recovery_workspace/temp/frag_{i}.bin",
                created_at=datetime.now(timezone.utc)
            )
            db.add(frag)

        # Seed AI analysis record
        ai_analysis = AIAnalysisRecord(
            id=uuid.uuid4(),
            file_id=file_rec.id,
            detected_file_type="image/jpeg",
            corruption_type="header_corruption_and_truncated_eoi",
            damaged_regions=[{"offset": 0, "length": 512, "type": "SOI_APP0_damage"}],
            predicted_structure={"containers": ["SOI", "DQT", "DHT", "SOF0", "SOS", "EOI"], "missing": ["EOI"]},
            confidence=91.0,
            explanation="JPEG SOI and DQT tables identified at alternative offset. Header rebuilt forensically.",
            model_name="forensic-neural-carver-v2",
            created_at=datetime.now(timezone.utc)
        )
        db.add(ai_analysis)

        # Seed recovery results record
        recovery_result = RecoveryResultRecord(
            id=uuid.uuid4(),
            file_id=file_rec.id,
            recovered_path=f"recovery_workspace/output/{file_id}_recovered.jpg",
            recovered_size=4180000,
            recovery_percentage=87.4,
            validation_status="PASS",
            validation_details={"magic_bytes_valid": True, "structure_valid": True, "pixel_decode": "OK"},
            output_hash="f5a79854e3fa7a34e00c85c2c77d4c1b52a13ef295a02e5b6140652758114f2e",
            created_at=datetime.now(timezone.utc)
        )
        db.add(recovery_result)

        # Seed audit log records
        audit_events = [
            ("JOB_CREATED", {"job_id": str(job.id), "user": user.email}),
            ("FILE_UPLOADED", {"filename": file_rec.original_name, "size": file_rec.file_size, "hash": file_rec.file_hash}),
            ("FILE_ANALYZED", {"detected_type": file_rec.detected_type, "damage_pct": file_rec.damage_percentage}),
            ("FRAGMENTS_DETECTED", {"count": 3, "valid_count": 3}),
            ("AI_ANALYSIS_COMPLETED", {"model": ai_analysis.model_name, "confidence": ai_analysis.confidence}),
            ("RECONSTRUCTION_STARTED", {"job_id": str(job.id)}),
            ("RECONSTRUCTION_COMPLETED", {"output_file": recovery_result.recovered_path, "bytes": recovery_result.recovered_size}),
            ("VALIDATION_COMPLETED", {"status": "PASS", "details": recovery_result.validation_details}),
            ("RECOVERY_COMPLETED", {"recovery_percentage": 87.4, "final_status": "completed"})
        ]

        for action, details in audit_events:
            audit = AuditLog(
                job_id=job.id,
                action=action,
                details=details,
                created_at=datetime.now(timezone.utc)
            )
            db.add(audit)

        db.commit()
        print(f"[+] Seeding complete. Created Job ID: {job.id}")
    except Exception as e:
        db.rollback()
        print(f"[!] Error seeding database: {e}")
        raise
    finally:
        db.close()


def check_connection():
    """Verify database connectivity and report health."""
    print(f"[*] Testing database connectivity to {settings.database_url}...")
    res = check_db_connection()
    if res.get("connected"):
        print("[+] DATABASE CONNECTION SUCCESSFUL!")
        for k, v in res.items():
            print(f"    {k}: {v}")
    else:
        print("[-] DATABASE CONNECTION FAILED!")
        for k, v in res.items():
            print(f"    {k}: {v}")


def check_status():
    """Report row counts across all forensic tables."""
    print(f"[*] Inspecting database tables...")
    res = check_db_connection()
    if not res.get("connected"):
        print("[-] Cannot connect to database.")
        return

    db = SessionLocal()
    try:
        tables = [
            ("users", User),
            ("recovery_jobs", RecoveryJob),
            ("files", FileRecord),
            ("fragments", FragmentRecord),
            ("ai_analysis", AIAnalysisRecord),
            ("recovery_results", RecoveryResultRecord),
            ("audit_logs", AuditLog),
        ]
        print("\n--- FORENSIC RECOVERY DATABASE STATUS ---")
        for table_name, model in tables:
            count = db.query(model).count()
            print(f"  {table_name.ljust(20)}: {count} records")
        print("------------------------------------------\n")
    except Exception as e:
        print(f"[!] Error querying status: {e}")
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="Forensic Recovery Database Management CLI")
    parser.add_argument("command", choices=["migrate", "reset", "seed", "check", "status"], help="Command to execute")
    args = parser.parse_args()

    if args.command == "migrate":
        run_migrations()
    elif args.command == "reset":
        reset_database()
    elif args.command == "seed":
        seed_database()
    elif args.command == "check":
        check_connection()
    elif args.command == "status":
        check_status()


if __name__ == "__main__":
    main()
