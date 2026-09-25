"""
Abstract File Format Plugin interface and forensic validation result contract.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from backend.recovery.fragments import Fragment

@dataclass
class ValidationResult:
    is_valid: bool
    decoder_success: bool
    dimensions: Optional[Tuple[int, int]] = None
    file_size: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    missing_regions: List[Dict[str, Any]] = field(default_factory=list)
    structural_score: float = 0.0 # 0 to 100
    details: Dict[str, Any] = field(default_factory=dict)

class FormatPlugin(ABC):
    """
    Format-specific parser, boundary checker, and validator.
    """
    format_name: str = "unknown"
    extensions: List[str] = []

    @abstractmethod
    def detect(self, data: bytes) -> bool:
        """Return True if byte stream matches this file format."""
        pass

    @abstractmethod
    def extract_features(self, data: bytes) -> Dict[str, Any]:
        """Extract format-specific structural metadata."""
        pass

    @abstractmethod
    def check_boundary(self, frag_a: Fragment, frag_b: Fragment) -> float:
        """Score transition compatibility between two fragments (0.0 to 1.0)."""
        pass

    def reconstruct(self, fragments: List[Fragment]) -> bytes:
        """
        Reconstruct file by assembling real original bytes in fragment sequence.
        NEVER creates or fabricates fake replacement bytes.
        """
        return b"".join(f.data for f in fragments)

    @abstractmethod
    def validate(self, data: bytes) -> ValidationResult:
        """
        Rigorous validation of reconstructed byte sequence.
        """
        pass
