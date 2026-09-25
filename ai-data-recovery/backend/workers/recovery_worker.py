"""
Asynchronous Recovery Job Worker.
Executes end-to-end recovery pipeline:
  Acquisition -> Hashing -> Filesystem Analysis -> Scanning -> Carving -> Fragment Extraction
  -> AI/ML Classification & Relationships -> Reconstruction -> Validation -> Audited Output
"""
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

from backend.config import settings
from backend.database.database import SessionLocal
from backend.database.models import (
    RecoveryJob, SourceAudit, FragmentRecord,
    FragmentRelationshipRecord, ReconstructionCandidateRecord,
    RecoveredFileRecord, AuditLog
)
from backend.storage.base import StorageSource
from backend.storage.file_source import FileSource
from backend.storage.disk_image import DiskImageSource
from backend.filesystem.ntfs import NTFSAnalyzer
from backend.filesystem.fat32 import FAT32Analyzer
from backend.filesystem.exfat import ExFATAnalyzer
from backend.recovery.scanner import RawStorageScanner
from backend.recovery.carving import FileCarver
from backend.recovery.fragments import Fragment, slice_bytes_into_fragments
from backend.ml.classifier import file_classifier
from backend.ml.relationship_model import relationship_model
from backend.ml.clustering import fragment_clusterer
from backend.recovery.reconstruction import ReconstructionEngine
from backend.recovery.confidence import ConfidenceEngine
from backend.security.audit import log_audit_event

logger = logging.getLogger("recovery_worker")

class RecoveryWorker:
    """
    Executes a forensic recovery job in an asynchronous background context.
    """
    def __init__(self, job_id: str):
        self.job_id = job_id
        self._cancelled = False

    def _is_job_cancelled(self, db) -> bool:
        job = db.query(RecoveryJob).filter(RecoveryJob.id == self.job_id).first()
        if job and job.status == "cancelled":
            self._cancelled = True
            return True
        return False

    def _update_stage(self, db, stage: str, progress: int, status: str = "in_progress"):
        job = db.query(RecoveryJob).filter(RecoveryJob.id == self.job_id).first()
        if job and job.status != "cancelled":
            job.current_stage = stage
            job.progress = progress
            if status:
                job.status = status
            db.commit()

    def run(self):
        db = SessionLocal()
        try:
            job = db.query(RecoveryJob).filter(RecoveryJob.id == self.job_id).first()
            if not job:
                logger.error(f"Job {self.job_id} not found.")
                return

            log_audit_event(self.job_id, "job_started", {"operation": job.operation, "source": job.source_path})

            # STAGE 1: Acquiring
            self._update_stage(db, "acquiring", 5, status="acquiring")
            source_path = Path(job.source_path)
            if not source_path.exists():
                raise FileNotFoundError(f"Authorized source does not exist: {source_path}")

            source: StorageSource
            if job.source_type == "disk_image":
                source = DiskImageSource(source_path)
            else:
                source = FileSource(source_path)

            source.open()

            # STAGE 2: Hashing
            self._update_stage(db, "hashing", 15, status="hashing")
            if self._is_job_cancelled(db):
                return
            sha256 = source.calculate_sha256()

            source_audit = SourceAudit(
                job_id=self.job_id,
                source_path=str(source_path.resolve()),
                source_sha256=sha256,
                source_size=source.get_size(),
                source_type=job.source_type,
                sector_size=source.get_sector_size(),
                filesystem_detected="unknown",
                is_read_only=True
            )
            db.add(source_audit)
            db.commit()

            # STAGE 3: Filesystem Analysis (Mode B / Disk Images)
            self._update_stage(db, "filesystem_analysis", 25, status="filesystem_analysis")
            if self._is_job_cancelled(db):
                return

            deleted_records = []
            detected_fs = "none"

            if job.source_type in ("disk_image", "partition"):
                for fs_cls in [NTFSAnalyzer, FAT32Analyzer, ExFATAnalyzer]:
                    analyzer = fs_cls(source)
                    if analyzer.detect():
                        info = analyzer.get_filesystem_info()
                        detected_fs = info.fs_type if info else "unknown"
                        source_audit.filesystem_detected = detected_fs
                        db.commit()
                        deleted_records = analyzer.find_deleted_files()
                        break

            # STAGE 4: Scanning & File Carving
            self._update_stage(db, "scanning", 40, status="scanning")
            if self._is_job_cancelled(db):
                return

            scanner = RawStorageScanner(source, block_size=4096)
            scan_report = scanner.scan(
                max_bytes=min(source.get_size(), 20 * 1024 * 1024),
                progress_callback=lambda cur, tot, msg: None
            )

            self._update_stage(db, "carving", 50, status="carving")
            if self._is_job_cancelled(db):
                return

            carver = FileCarver(source)
            carved_candidates = carver.carve_from_scan(scan_report, job_id=self.job_id)

            # STAGE 5: Fragment Extraction & Analysis
            self._update_stage(db, "fragment_analysis", 60, status="fragment_analysis")
            if self._is_job_cancelled(db):
                return

            all_fragments: List[Fragment] = []
            
            # If carving produced candidates, collect their fragments
            for c in carved_candidates:
                all_fragments.extend(c.fragments)

            # If dealing with a single uploaded corrupted file or no carved fragments found:
            if not all_fragments:
                # Slice source directly into fragments
                raw_bytes = source.read_bytes(0, source.get_size())
                all_fragments = slice_bytes_into_fragments(
                    raw_bytes,
                    job_id=self.job_id,
                    base_offset=0,
                    fragment_size=4096,
                    prefix_id="frag"
                )

            # Classify fragments and persist records
            for f in all_fragments:
                pred = file_classifier.predict(f.data)
                f.predicted_type = pred["predicted_type"]
                f.type_probabilities = pred["probabilities"]

                # Mark headers / footers
                if f.predicted_type == "jpeg":
                    if f.data.startswith(b"\xFF\xD8"):
                        f.is_header = True
                    if b"\xFF\xD9" in f.data[-4:]:
                        f.is_footer = True
                elif f.predicted_type == "png":
                    if f.data.startswith(b"\x89PNG"):
                        f.is_header = True
                    if b"IEND" in f.data[-16:]:
                        f.is_footer = True
                elif f.predicted_type == "pdf":
                    if b"%PDF" in f.data[:32]:
                        f.is_header = True
                    if b"%%EOF" in f.data[-32:]:
                        f.is_footer = True
                elif f.predicted_type == "zip":
                    if f.data.startswith(b"PK\x03\x04"):
                        f.is_header = True
                    if b"PK\x05\x06" in f.data[-64:]:
                        f.is_footer = True

                frag_rec = FragmentRecord(
                    id=f"{self.job_id}_{f.fragment_id}",
                    job_id=self.job_id,
                    source_offset=f.source_offset,
                    length=f.length,
                    sha256=f.sha256,
                    predicted_type=f.predicted_type,
                    type_probabilities=json.dumps(f.type_probabilities),
                    entropy=f.entropy,
                    status=f.status,
                    is_header=f.is_header,
                    is_footer=f.is_footer
                )
                db.add(frag_rec)
            db.commit()

            # STAGE 6: Fragment Relationships
            self._update_stage(db, "relationship_analysis", 70, status="relationship_analysis")
            if self._is_job_cancelled(db):
                return

            # Compute and store relationships for top transitions
            n_frags = len(all_fragments)
            for i in range(min(n_frags, 20)):
                for j in range(min(n_frags, 20)):
                    if i == j:
                        continue
                    fa, fb = all_fragments[i], all_fragments[j]
                    prob, rel_type, evidence = relationship_model.predict_successor(fa, fb)
                    if prob >= 0.20:
                        rel_rec = FragmentRelationshipRecord(
                            job_id=self.job_id,
                            from_fragment_id=fa.fragment_id,
                            to_fragment_id=fb.fragment_id,
                            probability=prob,
                            relationship_type=rel_type,
                            feature_metadata=json.dumps(evidence)
                        )
                        db.add(rel_rec)
            db.commit()

            # STAGE 7: Multi-File Clustering & Reconstruction
            self._update_stage(db, "reconstructing", 80, status="reconstructing")
            if self._is_job_cancelled(db):
                return

            clusters = fragment_clusterer.cluster_fragments(all_fragments)
            if not clusters:
                clusters = {"default_cluster": all_fragments}

            output_files = []

            for cluster_id, cluster_frags in clusters.items():
                if not cluster_frags:
                    continue

                target_fmt = job.target_type or cluster_frags[0].predicted_type
                engine = ReconstructionEngine(target_type=target_fmt)
                candidates = engine.reconstruct_and_evaluate(cluster_frags, max_candidates=3)

                if not candidates:
                    continue

                best_candidate = candidates[0]

                # Record candidate evaluations in database
                for cand in candidates:
                    cand_rec = ReconstructionCandidateRecord(
                        job_id=self.job_id,
                        rank=cand.rank,
                        fragment_sequence=json.dumps(cand.fragment_sequence),
                        score=cand.sequence_score,
                        parser_valid=cand.validation_result.decoder_success,
                        is_selected=cand.is_selected,
                        evidence_details=json.dumps(cand.evidence)
                    )
                    db.add(cand_rec)
                db.commit()

                # STAGE 8: Validation & Confidence Scoring
                self._update_stage(db, "validating", 90, status="validating")
                conf_report = ConfidenceEngine.evaluate(
                    fragments_used=best_candidate.fragments,
                    validation_result=best_candidate.validation_result,
                    avg_model_prob=best_candidate.avg_relationship_probability
                )

                # Write reconstructed output file to workspace
                ext = target_fmt if target_fmt != "unknown" else "bin"
                filename = job.target_filename or f"recovered_{self.job_id}_{cluster_id}.{ext}"
                if not filename.endswith(f".{ext}"):
                    filename = f"{filename}.{ext}"
                output_path = settings.output_dir / filename

                with open(output_path, "wb") as out_f:
                    out_f.write(best_candidate.reconstructed_bytes)

                recovered_rec = RecoveredFileRecord(
                    id=f"REC_FILE_{len(output_files) + 1}",
                    job_id=self.job_id,
                    filename=filename,
                    file_type=target_fmt,
                    output_path=str(output_path.resolve()),
                    sha256=source.calculate_sha256() if len(best_candidate.reconstructed_bytes) == source.get_size() else Fragment(
                        fragment_id="tmp", job_id=self.job_id, source_offset=0, length=len(best_candidate.reconstructed_bytes), data=best_candidate.reconstructed_bytes
                    ).sha256,
                    recovered_bytes=conf_report.recovered_bytes,
                    missing_bytes=conf_report.missing_bytes,
                    fabricated_bytes=0, # STRICT ZERO INVARIANT
                    recoverability_score=conf_report.recoverability_score,
                    integrity_score=conf_report.integrity_score,
                    model_confidence=conf_report.model_confidence,
                    status=conf_report.status,
                    validation_details=json.dumps({
                        "parser_success": best_candidate.validation_result.decoder_success,
                        "dimensions": best_candidate.validation_result.dimensions,
                        "errors": best_candidate.validation_result.errors,
                        "warnings": best_candidate.validation_result.warnings,
                        "evidence": conf_report.evidence
                    }),
                    fragments_used=json.dumps([f.fragment_id for f in best_candidate.fragments]),
                    missing_regions=json.dumps(conf_report.missing_regions)
                )
                db.add(recovered_rec)
                output_files.append(recovered_rec)
                db.commit()

            # Finalize Job
            self._update_stage(db, "completed", 100, status="completed")
            log_audit_event(
                self.job_id,
                "job_completed",
                {"files_recovered": len(output_files), "output_dir": str(settings.output_dir)}
            )

        except Exception as e:
            logger.exception(f"Error executing recovery job {self.job_id}: {str(e)}")
            job = db.query(RecoveryJob).filter(RecoveryJob.id == self.job_id).first()
            if job:
                job.status = "failed"
                job.error = str(e)
                db.commit()
            log_audit_event(self.job_id, "job_failed", {"error": str(e)})
        finally:
            db.close()
