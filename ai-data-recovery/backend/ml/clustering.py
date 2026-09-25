"""
Multi-File Fragment Clustering Engine.
Separates mixed fragments originating from different files using type predictions and embeddings.
"""
from typing import List, Dict, Any
import numpy as np
from sklearn.cluster import DBSCAN

from backend.recovery.fragments import Fragment
from backend.ml.embeddings import embedding_engine

class FragmentClusterer:
    """
    Partitions a mixed bag of fragments into candidate file clusters.
    """
    def __init__(self, eps: float = 0.45, min_samples: int = 1):
        self.eps = eps
        self.min_samples = min_samples

    def cluster_fragments(self, fragments: List[Fragment]) -> Dict[str, List[Fragment]]:
        """
        Group fragments first by predicted format, then cluster within each format.
        Returns a dictionary mapping cluster_id -> list of Fragments.
        """
        if not fragments:
            return {}

        # 1. Group by predicted file type
        type_groups: Dict[str, List[Fragment]] = {}
        for f in fragments:
            type_groups.setdefault(f.predicted_type, []).append(f)

        clusters: Dict[str, List[Fragment]] = {}
        cluster_counter = 1

        for ftype, frags in type_groups.items():
            if len(frags) <= 2:
                # Small group, assign to single candidate
                c_id = f"cluster_{ftype}_{cluster_counter}"
                clusters[c_id] = frags
                cluster_counter += 1
                continue

            # Embed each fragment
            vectors = np.array([embedding_engine.embed_fragment(f) for f in frags])
            
            # Run DBSCAN on cosine distance metric
            # Cosine distance = 1 - cosine similarity
            db = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric="cosine")
            labels = db.fit_predict(vectors)

            group_subclusters: Dict[int, List[Fragment]] = {}
            for label, frag in zip(labels, frags):
                group_subclusters.setdefault(label, []).append(frag)

            for label, sub_frags in group_subclusters.items():
                c_id = f"cluster_{ftype}_{cluster_counter}"
                clusters[c_id] = sub_frags
                cluster_counter += 1

        return clusters

# Global singleton
fragment_clusterer = FragmentClusterer()
