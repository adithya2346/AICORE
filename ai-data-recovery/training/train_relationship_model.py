"""
Training script for AI Model 2: Fragment Relationship Model.
"""
from backend.config import settings
from backend.ml.relationship_model import relationship_model
from training.prepare_data import prepare_relationship_dataset

def main():
    print("Loading synthetic training dataset for Fragment Relationship Model...")
    X, y = prepare_relationship_dataset(settings.datasets_dir)
    print(f"Relationship pair feature shape: {X.shape}, positive ratio: {float(y.mean()):.2f}")
    
    relationship_model.fit(X, y)
    print(f"Model successfully trained and saved to {relationship_model.model_path}")

if __name__ == "__main__":
    main()
