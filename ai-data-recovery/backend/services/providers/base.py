"""
Base Abstract Interface and Data Models for AI Image Restoration Providers.
Ensures loose coupling so providers (OpenAI, Gemini, Stability, Mock) can be swapped seamlessly.
"""
import io
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Union
from pydantic import BaseModel
from PIL import Image

class AIRestorationResult(BaseModel):
    success: bool
    restored_bytes: Optional[bytes] = None
    mask_bytes: Optional[bytes] = None
    provider_name: str
    model_name: str = "default"
    confidence: float = 0.85
    error_message: Optional[str] = None
    latency_ms: float = 0.0
    pixels_restored_count: int = 0
    total_pixels: int = 0

    class Config:
        arbitrary_types_allowed = True

    @property
    def restored_image(self) -> Optional[Image.Image]:
        if self.restored_bytes:
            try:
                return Image.open(io.BytesIO(self.restored_bytes)).convert("RGB")
            except Exception:
                return None
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "provider": self.provider_name,
            "model": self.model_name,
            "confidence": self.confidence,
            "error": self.error_message,
            "latency_ms": self.latency_ms,
            "has_restored_bytes": self.restored_bytes is not None,
            "pixels_restored": self.pixels_restored_count,
            "total_pixels": self.total_pixels
        }


class AIRestorationProvider(ABC):
    """
    Abstract Base Class for AI image inpainting / restoration adapters.
    All implementations must never log or expose API keys.
    """
    def __init__(self, api_key: Optional[str] = None, model: str = "default", timeout_seconds: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    @property
    def provider_name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def restore_image(
        self,
        original_image: Optional[Image.Image] = None,
        damage_mask: Optional[Image.Image] = None,
        image_bytes: Optional[bytes] = None,
        mask_bytes: Optional[bytes] = None,
        prompt: Optional[str] = None
    ) -> AIRestorationResult:
        """
        Send recoverable image data and damage mask to AI restoration API.
        Accepts either PIL Images or bytes.
        """
        pass
