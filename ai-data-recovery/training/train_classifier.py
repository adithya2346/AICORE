"""
Training script for AI Model 1: File Type Classifier.
"""
from backend.config import settings
from backend.ml.classifier import file_classifier
from training.prepare_data import prepare_classifier_dataset

def main():
    print("Loading synthetic training dataset for File Classifier...")
    X, y = prepare_classifier_dataset(settings.datasets_dir)
    print(f"Dataset shape: {X.shape}, classes: {set(y)}")
    
    file_classifier.fit(X, y)
    print(f"Model successfully trained and saved to {file_classifier.model_path}")

if __name__ == "__main__":
    main()
