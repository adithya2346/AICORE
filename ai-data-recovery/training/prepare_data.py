"""
Data Preparation for Training Fragment Classifiers and Relationship Models.
Generates single-fragment feature matrices and balanced positive/negative transition pairs.
"""
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
import numpy as np

from backend.config import settings
from backend.recovery.fragments import Fragment
from backend.ml.features import extract_single_fragment_features, extract_pair_features

def load_dataset_fragments(dataset_dir: Path) -> List[Tuple[Fragment, Dict[str, Any]]]:
    meta_path = dataset_dir / "ground_truth_metadata.json"
    frags_dir = dataset_dir / "fragments"
    
    if not meta_path.exists():
        raise FileNotFoundError(f"Dataset metadata not found at {meta_path}. Run generate_dataset.py first.")

    with open(meta_path, "r") as f:
        meta_list = json.load(f)

    loaded = []
    for m in meta_list:
        frag_file = frags_dir / f"{m['fragment_id']}.bin"
        if frag_file.exists():
            with open(frag_file, "rb") as f:
                data = f.read()
            frag = Fragment(
                fragment_id=m["fragment_id"],
                job_id="training",
                source_offset=m["original_offset"],
                length=m["fragment_length"],
                data=data,
                predicted_type=m["file_type"]
            )
            loaded.append((frag, m))
            
    return loaded

def prepare_classifier_dataset(dataset_dir: Path) -> Tuple[np.ndarray, List[str]]:
    """Build (X, y) for file type classification."""
    frags_with_meta = load_dataset_fragments(dataset_dir)
    X_list = []
    y_list = []

    for frag, meta in frags_with_meta:
        feat = extract_single_fragment_features(frag.data)
        X_list.append(feat)
        y_list.append(meta["file_type"])

    return np.array(X_list, dtype=np.float32), y_list

def prepare_relationship_dataset(dataset_dir: Path) -> Tuple[np.ndarray, np.ndarray]:
    """
    Build positive (A -> correct B) and negative (A -> incorrect B) pair features.
    """
    frags_with_meta = load_dataset_fragments(dataset_dir)
    frag_map = {m["fragment_id"]: (frag, m) for frag, m in frags_with_meta}

    X_pairs = []
    y_pairs = []

    # 1. Positive Pairs
    for fid, (frag_a, meta_a) in frag_map.items():
        next_fid = meta_a.get("correct_next_fragment")
        if next_fid and next_fid in frag_map:
            frag_b = frag_map[next_fid][0]
            feat = extract_pair_features(frag_a, frag_b)
            X_pairs.append(feat)
            y_pairs.append(1) # Positive transition

    # 2. Negative Pairs (random non-successors)
    all_fids = list(frag_map.keys())
    for fid, (frag_a, meta_a) in frag_map.items():
        correct_next = meta_a.get("correct_next_fragment")
        # Pick 2 negative candidates
        for _ in range(2):
            neg_fid = np.random.choice(all_fids)
            if neg_fid != fid and neg_fid != correct_next:
                frag_neg = frag_map[neg_fid][0]
                feat = extract_pair_features(frag_a, frag_neg)
                X_pairs.append(feat)
                y_pairs.append(0) # Negative transition

    return np.array(X_pairs, dtype=np.float32), np.array(y_pairs, dtype=np.int32)
