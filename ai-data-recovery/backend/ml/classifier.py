"""
AI Model 1: File Type Classification Engine.
Predicts file type from fragment binary features using RandomForest with deterministic fallback heuristics.
"""
from pathlib import Path
from typing import Dict, Any, Optional, List
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from backend.config import settings
from backend.ml.features import extract_single_fragment_features, SUPPORTED_TYPES

MODEL_PATH = settings.models_dir / "file_classifier.joblib"

class FileTypeClassifier:
    """
    Predicts the file format of arbitrary raw fragments.
    """
    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or MODEL_PATH
        self.model: Optional[RandomForestClassifier] = None
        self.classes: List[str] = SUPPORTED_TYPES
        self.load()

    def load(self) -> bool:
        if self.model_path.exists():
            try:
                data = joblib.load(self.model_path)
                self.model = data.get("model")
                self.classes = data.get("classes", SUPPORTED_TYPES)
                return True
            except Exception:
                pass
        return False

    def save(self) -> None:
        if self.model:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({"model": self.model, "classes": self.classes}, self.model_path)

    def fit(self, X: np.ndarray, y: List[str]) -> None:
        clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
        clf.fit(X, y)
        self.model = clf
        self.classes = list(clf.classes_)
        self.save()

    def _heuristic_predict(self, data: bytes) -> Dict[str, Any]:
        """
        Deterministic binary heuristic fallback when trained weights are pending.
        """
        if not data:
            return {"predicted_type": "unknown", "probabilities": {"unknown": 1.0}}
            
        probs = {t: 0.05 for t in self.classes}
        
        # Check magic bytes directly
        prefix = data[:16]
        if b"\xFF\xD8\xFF" in prefix:
            probs["jpeg"] = 0.95
        elif b"\x89PNG" in prefix:
            probs["png"] = 0.95
        elif b"%PDF" in prefix:
            probs["pdf"] = 0.95
        elif b"PK\x03\x04" in prefix:
            probs["zip"] = 0.95
        elif b"ftyp" in prefix:
            probs["mp4"] = 0.95
        elif b"ID3" in prefix:
            probs["mp3"] = 0.95
        elif b"SQLite format 3" in prefix:
            probs["sqlite"] = 0.95
        else:
            # Statistical characteristics
            # High entropy (> 7.2) with many 0xFF bytes typical of JPEG scan data
            ff_count = data.count(b"\xFF")
            ff_ratio = ff_count / len(data)
            
            # Check for JPEG restart markers or 0xFF00 byte stuffing
            if ff_ratio > 0.005 and b"\xFF\x00" in data:
                probs["jpeg"] = 0.70
            elif b"/Type" in data or b"/Pages" in data or b"stream\n" in data:
                probs["pdf"] = 0.80
            elif b"IHDR" in data or b"IDAT" in data:
                probs["png"] = 0.85
            else:
                probs["unknown"] = 0.60
                
        # Normalize
        total = sum(probs.values())
        norm_probs = {k: round(v / total, 4) for k, v in probs.items()}
        best_type = max(norm_probs.items(), key=lambda item: item[1])[0]
        
        return {
            "predicted_type": best_type,
            "probabilities": norm_probs
        }

    def predict(self, data: bytes) -> Dict[str, Any]:
        """
        Predict file format distribution for raw bytes.
        """
        if self.model is not None:
            try:
                features = extract_single_fragment_features(data).reshape(1, -1)
                proba = self.model.predict_proba(features)[0]
                prob_dict = {cls: round(float(p), 4) for cls, p in zip(self.classes, proba)}
                best_type = max(prob_dict.items(), key=lambda item: item[1])[0]
                return {
                    "predicted_type": best_type,
                    "probabilities": prob_dict
                }
            except Exception:
                pass
                
        return self._heuristic_predict(data)

# Global singleton
file_classifier = FileTypeClassifier()
