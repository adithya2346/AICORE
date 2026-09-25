"""
Forensic audit logging for digital evidence integrity and chain-of-custody tracking.
"""
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from backend.config import settings

logger = logging.getLogger("forensic_audit")
logger.setLevel(logging.INFO)

AUDIT_LOG_FILE = settings.workspace_dir / "forensic_audit.log"
if not AUDIT_LOG_FILE.parent.exists():
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

file_handler = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
formatter = logging.Formatter(
    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "event": %(message)s}'
)
file_handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(file_handler)

def log_audit_event(
    job_id: str,
    action: str,
    details: Dict[str, Any],
    source_sha256: Optional[str] = None,
    read_only_verified: bool = True
) -> Dict[str, Any]:
    """
    Log an immutable forensic chain-of-custody event.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "job_id": job_id,
        "action": action,
        "read_only_verified": read_only_verified,
        "source_sha256": source_sha256,
        "details": details
    }
    logger.info(json.dumps(record))
    return record
