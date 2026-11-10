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

# Database Configuration (Defaults to zero-configuration local SQLite recovery.db)
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "data_recovery")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

if os.getenv("DATABASE_URL"):
    RAW_DATABASE_URL = os.getenv("DATABASE_URL")
elif os.getenv("DB_HOST") and os.getenv("DB_USER") and os.getenv("DB_PASSWORD"):
    RAW_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
else:
    # Default to local persistent SQLite database
    RAW_DATABASE_URL = f"sqlite:///{BASE_DIR}/recovery.db"

# Normalize postgres:// to postgresql:// for SQLAlchemy compatibility if provided
if RAW_DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    DATABASE_URL = RAW_DATABASE_URL


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
    
    # Database Settings
    db_host: str = DB_HOST
    db_port: int = int(DB_PORT) if str(DB_PORT).isdigit() else 5432
    db_name: str = DB_NAME
    db_user: str = DB_USER
    db_password: Optional[str] = DB_PASSWORD
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
