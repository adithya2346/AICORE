"""
AI Model 3: Fragment Embedding Engine.
Generates fixed-dimensional normalized vector representations for fragments
to enable semantic clustering, similarity searches, and multi-file separation.
"""
import numpy as np
from typing import Tuple
from backend.recovery.fragments import Fragment
from backend.ml.features import extract_single_fragment_features

EMBEDDING_DIM = 64

class FragmentEmbeddingEngine:
    """
    Computes normalized embeddings for fragments and provides similarity metrics.
    """
    def __init__(self):
        np.random.seed(42)
        self.projection_matrix = None

    def embed(self, data: bytes) -> np.ndarray:
        """Extract features and project into normalized 64-dimensional latent embedding."""
        raw_feat = extract_single_fragment_features(data)
        if self.projection_matrix is None or self.projection_matrix.shape[0] != len(raw_feat):
            np.random.seed(42)
            self.projection_matrix = np.random.normal(0, 1.0 / np.sqrt(EMBEDDING_DIM), (len(raw_feat), EMBEDDING_DIM)).astype(np.float32)
        projected = np.dot(raw_feat, self.projection_matrix)
        norm = np.linalg.norm(projected)
        if norm > 0:
            projected /= norm
        return projected

    def embed_fragment(self, fragment: Fragment) -> np.ndarray:
        return self.embed(fragment.data)

    @staticmethod
    def cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity between two unit vectors: in range [-1.0, 1.0]."""
        dot = float(np.dot(vec1, vec2))
        return max(-1.0, min(1.0, dot))

    @staticmethod
    def euclidean_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Convert Euclidean distance into a similarity metric in range [0.0, 1.0]."""
        dist = float(np.linalg.norm(vec1 - vec2))
        return 1.0 / (1.0 + dist)

# Global singleton
embedding_engine = FragmentEmbeddingEngine()
