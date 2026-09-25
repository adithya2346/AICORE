"""
Feature extraction utility script for offline batch dataset conversion.
"""
from pathlib import Path
import numpy as np
from backend.config import settings
from training.prepare_data import prepare_classifier_dataset, prepare_relationship_dataset

def run_extraction():
    dataset_dir = settings.datasets_dir
    print(f"Extracting features from {dataset_dir}...")
    X_cls, y_cls = prepare_classifier_dataset(dataset_dir)
    print(f"File Classifier features extracted: {X_cls.shape}, Labels: {len(y_cls)}")
    
    X_rel, y_rel = prepare_relationship_dataset(dataset_dir)
    print(f"Relationship pair features extracted: {X_rel.shape}, Target pairs: {len(y_rel)}")
    
    return X_cls, y_cls, X_rel, y_rel

if __name__ == "__main__":
    run_extraction()
