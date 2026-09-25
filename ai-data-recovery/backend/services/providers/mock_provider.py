"""
Mock AI Restoration Provider for deterministic offline testing and fallbacks.
Performs procedural inpainting on damaged regions without external API calls.
"""
import io
import time
from typing import Optional
from PIL import Image, ImageFilter
from backend.services.providers.base import AIRestorationProvider, AIRestorationResult

class MockAIRestorationProvider(AIRestorationProvider):
    """
    Mock adapter that simulates an AI restoration API.
    Used for unit testing, CI pipelines, and offline demonstrations.
    """
    def __init__(self, api_key: Optional[str] = None, model: str = "mock-inpaint-v1", timeout_seconds: int = 5):
        super().__init__(api_key=api_key or "mock_key", model=model, timeout_seconds=timeout_seconds)

    @property
    def provider_name(self) -> str:
        return "mock"

    def restore_image(
        self,
        original_image: Optional[Image.Image] = None,
        damage_mask: Optional[Image.Image] = None,
        image_bytes: Optional[bytes] = None,
        mask_bytes: Optional[bytes] = None,
        prompt: Optional[str] = None
    ) -> AIRestorationResult:
        start_time = time.time()
        try:
            # Resolve image
            if original_image is not None:
                img = original_image.convert("RGB")
            elif image_bytes is not None:
                img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            else:
                raise ValueError("Neither original_image nor image_bytes provided.")

            # Resolve mask
            if damage_mask is not None:
                mask = damage_mask.convert("L")
            elif mask_bytes is not None:
                mask = Image.open(io.BytesIO(mask_bytes)).convert("L")
            else:
                mask = Image.new("L", img.size, 255)

            # Ensure mask matches image dimensions
            if mask.size != img.size:
                mask = mask.resize(img.size, Image.Resampling.NEAREST)

            width, height = img.size
            total_pixels = width * height

            # Count damaged pixels (mask > 128)
            mask_data = mask.getdata()
            damaged_pixels = sum(1 for p in mask_data if p > 128)

            # Procedural inpainting for damaged areas:
            # Blur intact background to simulate coherent seamless reconstruction
            blurred_base = img.filter(ImageFilter.BoxBlur(radius=15))
            
            # Composite: preserve authentic pixels where mask is black (0), inpaint where white (255)
            restored = Image.composite(blurred_base, img, mask)

            out_buf = io.BytesIO()
            restored.save(out_buf, format="JPEG", quality=95)
            out_bytes = out_buf.getvalue()

            latency = round((time.time() - start_time) * 1000, 2)
            return AIRestorationResult(
                success=True,
                restored_bytes=out_bytes,
                mask_bytes=mask_bytes,
                provider_name="mock",
                model_name=self.model,
                confidence=0.88,
                latency_ms=latency,
                pixels_restored_count=damaged_pixels,
                total_pixels=total_pixels
            )
        except Exception as e:
            return AIRestorationResult(
                success=False,
                provider_name="mock",
                model_name=self.model,
                error_message=f"Mock restoration error: {str(e)}",
                latency_ms=round((time.time() - start_time) * 1000, 2)
            )
