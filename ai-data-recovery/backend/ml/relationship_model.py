"""
AI Model 2: Primary Fragment Relationship Model.
Predicts how likely Fragment B is to be the immediate successor of Fragment A.
Combines binary structural checks with statistical ML feature scoring.
"""
from pathlib import Path
from typing import Tuple, Dict, Any, Optional, List
import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier

from backend.config import settings
from backend.recovery.fragments import Fragment
from backend.ml.features import extract_pair_features

RELATIONSHIP_MODEL_PATH = settings.models_dir / "relationship_model.joblib"

class FragmentRelationshipModel:
    """
    Evaluates pairwise transition compatibility: Fragment A -> Fragment B.
    """
    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or RELATIONSHIP_MODEL_PATH
        self.model: Optional[GradientBoostingClassifier] = None
        self.version = "v1.0-hybrid-gb"
        self.load()

    def load(self) -> bool:
        if self.model_path.exists():
            try:
                data = joblib.load(self.model_path)
                self.model = data.get("model")
                self.version = data.get("version", self.version)
                return True
            except Exception:
                pass
        return False

    def save(self) -> None:
        if self.model:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({"model": self.model, "version": self.version}, self.model_path)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        clf = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        clf.fit(X, y)
        self.model = clf
        self.save()

    def _heuristic_successor_probability(self, frag_a: Fragment, frag_b: Fragment) -> Tuple[float, str, Dict[str, Any]]:
        """
        Deterministic binary and statistical rule engine for successor probability.
        """
        if frag_a.fragment_id == frag_b.fragment_id:
            return 0.0, "duplicate", {"reason": "self_loop"}

        # 1. Structural role constraints
        if frag_a.is_footer:
            return 0.0, "incompatible", {"reason": "frag_a_is_footer"}
        if frag_b.is_header:
            return 0.0, "incompatible", {"reason": "frag_b_is_header"}

        score = 0.50
        evidence: Dict[str, Any] = {}

        # 2. File type compatibility
        if frag_a.predicted_type != "unknown" and frag_b.predicted_type != "unknown":
            if frag_a.predicted_type == frag_b.predicted_type:
                score += 0.20
                evidence["type_match"] = frag_a.predicted_type
            else:
                score -= 0.40
                evidence["type_mismatch"] = f"{frag_a.predicted_type} vs {frag_b.predicted_type}"

        # 3. Entropy continuity
        entropy_delta = abs(frag_a.entropy - frag_b.entropy)
        if entropy_delta < 0.25:
            score += 0.15
            evidence["entropy_continuity"] = f"delta={entropy_delta:.3f}"
        elif entropy_delta > 1.5:
            score -= 0.15
            evidence["entropy_discontinuity"] = f"delta={entropy_delta:.3f}"

        # 4. Boundary transitions
        tail_a = frag_a.suffix_bytes[-4:] if len(frag_a.suffix_bytes) >= 4 else frag_a.data[-4:]
        head_b = frag_b.prefix_bytes[:4] if len(frag_b.prefix_bytes) >= 4 else frag_b.data[:4]

        # Check JPEG entropy coding boundaries: 0xFF must be followed by 0x00 or RST marker
        if frag_a.predicted_type == "jpeg" or frag_b.predicted_type == "jpeg":
            if tail_a and tail_a[-1] == 0xFF:
                if head_b and head_b[0] not in (0x00, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD9):
                    return 0.01, "incompatible", {"reason": "jpeg_illegal_byte_after_0xFF"}
                elif head_b and head_b[0] == 0x00:
                    score += 0.25
                    evidence["jpeg_byte_stuffing_verified"] = True

        # Check contiguous source offset
        expected_next_offset = frag_a.source_offset + frag_a.length
        if frag_b.source_offset == expected_next_offset and frag_a.source_offset > 0:
            score += 0.20
            evidence["contiguous_offset"] = True

        prob = max(0.01, min(0.99, score))
        rel_type = "likely_successor" if prob >= 0.70 else ("possible_successor" if prob >= 0.40 else "unlikely")
        return round(prob, 3), rel_type, evidence

    def predict_successor(self, frag_a: Fragment, frag_b: Fragment) -> Tuple[float, str, Dict[str, Any]]:
        """
        Predict probability of Frag B succeeding Frag A.
        Combines ML model output with deterministic checks.
        """
        h_prob, h_rel, h_evidence = self._heuristic_successor_probability(frag_a, frag_b)
        
        # Hard constraints that override any ML prediction
        if h_prob <= 0.05 or "reason" in h_evidence:
            return h_prob, h_rel, h_evidence

        if self.model is not None:
            try:
                pair_feat = extract_pair_features(frag_a, frag_b).reshape(1, -1)
                ml_prob = float(self.model.predict_proba(pair_feat)[0, 1])
                # Blended ensemble
                blended = round((ml_prob * 0.60) + (h_prob * 0.40), 3)
                rel_type = "likely_successor" if blended >= 0.70 else ("possible_successor" if blended >= 0.40 else "unlikely")
                h_evidence["ml_confidence"] = round(ml_prob, 3)
                return blended, rel_type, h_evidence
            except Exception:
                pass

        return h_prob, h_rel, h_evidence

# Global singleton
relationship_model = FragmentRelationshipModel()
