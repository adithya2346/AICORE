"""
Application configuration for AI-assisted Data Recovery System.
"""
from pathlib import Path
from pydantic import BaseModel
from typing import Optional
import os

try:
    from dotenv import load_dotenv
    # Search for .env in current and parent directory
    base_path = Path(__file__).resolve().parent.parent
    for env_path in [base_path / ".env", base_path.parent / ".env"]:
        if env_path.exists():
            load_dotenv(dotenv_path=env_path)
            break
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR / "recovery_workspace"
INPUT_DIR = WORKSPACE_DIR / "input"
OUTPUT_DIR = WORKSPACE_DIR / "output"
WORKING_COPIES_DIR = WORKSPACE_DIR / "working_copies"
TEMP_DIR = WORKSPACE_DIR / "temp"
MODELS_DIR = BASE_DIR / "models"
DATASETS_DIR = BASE_DIR / "datasets"

# Ensure runtime directories exist
for path in [WORKSPACE_DIR, INPUT_DIR, OUTPUT_DIR, WORKING_COPIES_DIR, TEMP_DIR, MODELS_DIR, DATASETS_DIR]:
    path.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/recovery.db")

class Settings(BaseModel):
    app_name: str = "AI-Assisted Intelligent Data Recovery & Digital Evidence Reconstruction"
    version: str = "1.0.0"
    base_dir: Path = BASE_DIR
    workspace_dir: Path = WORKSPACE_DIR
    input_dir: Path = INPUT_DIR
    output_dir: Path = OUTPUT_DIR
    working_copies_dir: Path = WORKING_COPIES_DIR
    temp_dir: Path = TEMP_DIR
    models_dir: Path = MODELS_DIR
    datasets_dir: Path = DATASETS_DIR
    database_url: str = DATABASE_URL
    default_scan_block_size: int = 4096
    max_memory_buffer_bytes: int = 64 * 1024 * 1024  # 64 MB
    entropy_threshold_high: float = 7.2  # Highly compressed/encrypted
    entropy_threshold_low: float = 1.0   # Highly sparse/repetitive
    model_version: str = "v1.0-rf-hybrid"
    
    # AI Restoration Service Settings
    ai_api_key: Optional[str] = os.getenv("AI_API_KEY")
    ai_provider: str = os.getenv("AI_PROVIDER", "openai").lower()
    ai_model: str = os.getenv("AI_MODEL", "dall-e-2")
    max_upload_size_mb: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
    recovery_timeout_seconds: int = int(os.getenv("RECOVERY_TIMEOUT_SECONDS", "30"))

settings = Settings()
