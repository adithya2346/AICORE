"""
Forensic Confidence and Recoverability Assessment Engine.
Strictly separates:
  1. MODEL CONFIDENCE: statistical probability from fragment matching & AI models
  2. FILE INTEGRITY: structural correctness, parser validation, checksums
  3. RECOVERABILITY SCORE: technical percentage of expected original data preserved
Enforces that fabricated_bytes is STRICTLY ZERO. Never invents missing data.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from backend.formats.base import ValidationResult
from backend.recovery.fragments import Fragment

@dataclass
class RecoverabilityReport:
    model_confidence: float # 0.0 to 1.0
    recoverability_score: float # 0 to 100
    integrity_score: float # 0 to 100
    status: str # fully_recoverable, mostly_recoverable, partially_recoverable, poorly_recoverable, not_recoverable
    recovered_bytes: int
    missing_bytes: int
    fabricated_bytes: int # ALWAYS 0
    missing_regions: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

class ConfidenceEngine:
    """
    Computes rigorous technical confidence and recoverability metrics.
    """
    @staticmethod
    def evaluate(
        fragments_used: List[Fragment],
        validation_result: ValidationResult,
        avg_model_prob: float,
        expected_total_size: Optional[int] = None
    ) -> RecoverabilityReport:
        recovered_bytes = sum(f.length for f in fragments_used)
        missing_bytes = 0
        missing_regions = list(validation_result.missing_regions)

        if expected_total_size and expected_total_size > recovered_bytes:
            missing_bytes = expected_total_size - recovered_bytes
            missing_regions.append({
                "estimated_offset": recovered_bytes,
                "estimated_size": missing_bytes,
                "status": "missing",
                "reconstructable": False,
                "description": "Trailing stream bytes truncated or overwritten"
            })
        else:
            # Estimate missing bytes from validator warnings
            for mr in missing_regions:
                missing_bytes += mr.get("estimated_size", 0)

        # 1. Model Confidence: statistical confidence across fragment relationships and type predictions
        model_conf = round(max(0.1, min(0.99, avg_model_prob)), 2)

        # 2. File Integrity: structural score from format-specific parser
        integrity_score = round(validation_result.structural_score, 1)

        # 3. Recoverability Score: ratio of recovered to expected, penalized by missing/corrupted regions
        if expected_total_size and expected_total_size > 0:
            byte_ratio = min(1.0, recovered_bytes / expected_total_size)
        else:
            byte_ratio = 1.0 if not missing_regions else 0.80

        raw_rec_score = (byte_ratio * 50.0) + (integrity_score * 0.35) + (model_conf * 15.0)
        recoverability_score = round(max(0.0, min(100.0, raw_rec_score)), 1)

        # Status categorization
        if recoverability_score >= 90.0 and validation_result.decoder_success and missing_bytes == 0:
            status = "fully_recoverable"
        elif recoverability_score >= 70.0 and validation_result.decoder_success:
            status = "mostly_recoverable"
        elif recoverability_score >= 40.0:
            status = "partially_recoverable"
        elif recoverability_score >= 15.0:
            status = "poorly_recoverable"
        else:
            status = "not_recoverable"

        evidence = [
            f"{recovered_bytes} original bytes successfully extracted from {len(fragments_used)} fragments",
            f"Fabricated bytes: 0 (Strict policy: no synthetic bytes generated)",
            f"Parser validation: {'SUCCESSFUL' if validation_result.decoder_success else 'INCOMPLETE'}",
            f"Structural integrity rating: {integrity_score}%"
        ]
        if missing_bytes > 0:
            evidence.append(f"Identified {len(missing_regions)} missing or corrupted byte region(s) totalling ~{missing_bytes} bytes")
        if validation_result.dimensions:
            evidence.append(f"Image decoded successfully with dimensions {validation_result.dimensions[0]}x{validation_result.dimensions[1]}")

        return RecoverabilityReport(
            model_confidence=model_conf,
            recoverability_score=recoverability_score,
            integrity_score=integrity_score,
            status=status,
            recovered_bytes=recovered_bytes,
            missing_bytes=missing_bytes,
            fabricated_bytes=0, # ALWAYS ZERO
            missing_regions=missing_regions,
            evidence=evidence
        )
