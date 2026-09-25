"""
Validation Engine for reconstructed binary evidence.
Invokes format-specific validators and performs cross-checking.
"""
from typing import Optional
from backend.formats import get_format_plugin, detect_format_plugin
from backend.formats.base import ValidationResult

class ValidationEngine:
    """
    Central validation engine for reconstructed artifacts.
    """
    @staticmethod
    def validate_bytes(data: bytes, format_hint: Optional[str] = None) -> ValidationResult:
        plugin = get_format_plugin(format_hint) if format_hint else None
        if not plugin:
            plugin = detect_format_plugin(data)
            
        if plugin:
            return plugin.validate(data)
            
        # Generic binary validation fallback
        return ValidationResult(
            is_valid=len(data) > 0,
            decoder_success=len(data) > 0,
            file_size=len(data),
            structural_score=50.0,
            details={"format": "raw_binary"}
        )
