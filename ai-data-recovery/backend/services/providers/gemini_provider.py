"""
Google Gemini / Imagen AI Restoration Provider.
Secured: API keys are read from environment, never logged, and never sent to clients.
"""
import io
import time
import base64
from typing import Optional
import httpx
from PIL import Image
from backend.services.providers.base import AIRestorationProvider, AIRestorationResult

class GeminiRestorationProvider(AIRestorationProvider):
    """
    Google Gemini / Imagen Restoration Adapter.
    Uses Google AI endpoints for semantic image editing and inpainting.
    """
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "imagen-3.0-generate-002",
        timeout_seconds: int = 30
    ):
        super().__init__(api_key=api_key, model=model, timeout_seconds=timeout_seconds)

    @property
    def provider_name(self) -> str:
        return "gemini"

    def restore_image(
        self,
        original_image: Optional[Image.Image] = None,
        damage_mask: Optional[Image.Image] = None,
        image_bytes: Optional[bytes] = None,
        mask_bytes: Optional[bytes] = None,
        prompt: Optional[str] = None
    ) -> AIRestorationResult:
        start_time = time.time()
        if not self.api_key or self.api_key.strip() in ("", "your_api_key_here"):
            return AIRestorationResult(
                success=False,
                provider_name="gemini",
                model_name=self.model,
                error_message="Missing Gemini API key. Configure AI_API_KEY in server environment.",
                latency_ms=0.0
            )

        try:
            # Resolve image
            if original_image is not None:
                img = original_image.convert("RGB")
            elif image_bytes is not None:
                img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            else:
                raise ValueError("Neither original_image nor image_bytes provided.")

            width, height = img.size
            total_pixels = width * height

            # Resolve mask
            if damage_mask is not None:
                mask = damage_mask.convert("L")
            elif mask_bytes is not None:
                mask = Image.open(io.BytesIO(mask_bytes)).convert("L")
            else:
                mask = Image.new("L", img.size, 255)

            if mask.size != img.size:
                mask = mask.resize(img.size, Image.Resampling.NEAREST)

            damaged_pixels = sum(1 for p in mask.getdata() if p > 128)

            img_buf = io.BytesIO()
            img.save(img_buf, format="JPEG", quality=90)
            b64_img = base64.b64encode(img_buf.getvalue()).decode("utf-8")

            mask_buf = io.BytesIO()
            mask.save(mask_buf, format="PNG")
            b64_mask = base64.b64encode(mask_buf.getvalue()).decode("utf-8")

            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:predict"
            headers = {
                "x-goog-api-key": self.api_key,
                "Content-Type": "application/json"
            }
            
            payload = {
                "instances": [
                    {
                        "prompt": prompt or "Forensically reconstruct damaged regions of this photograph naturally.",
                        "image": {
                            "bytesBase64Encoded": b64_img
                        },
                        "mask": {
                            "bytesBase64Encoded": b64_mask
                        }
                    }
                ],
                "parameters": {
                    "sampleCount": 1,
                    "editMode": "INPAINT_INSERT"
                }
            }

            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(endpoint, headers=headers, json=payload)

            latency = round((time.time() - start_time) * 1000, 2)

            if resp.status_code == 401 or resp.status_code == 403:
                return AIRestorationResult(
                    success=False,
                    provider_name="gemini",
                    model_name=self.model,
                    error_message="Authentication failed: Invalid Gemini API Key or unauthorized access.",
                    latency_ms=latency
                )
            elif resp.status_code == 429:
                return AIRestorationResult(
                    success=False,
                    provider_name="gemini",
                    model_name=self.model,
                    error_message="Gemini quota limit exceeded.",
                    latency_ms=latency
                )
            elif resp.status_code != 200:
                return AIRestorationResult(
                    success=False,
                    provider_name="gemini",
                    model_name=self.model,
                    error_message=f"Gemini API Error ({resp.status_code}): {resp.text[:250]}",
                    latency_ms=latency
                )

            data = resp.json()
            predictions = data.get("predictions", [])
            if not predictions or "bytesBase64Encoded" not in predictions[0]:
                return AIRestorationResult(
                    success=False,
                    provider_name="gemini",
                    model_name=self.model,
                    error_message="Gemini response did not contain restored image data.",
                    latency_ms=latency
                )

            restored_b64 = predictions[0]["bytesBase64Encoded"]
            restored_raw = base64.b64decode(restored_b64)

            # Composite strictly over damage mask to safeguard original pixels
            gen_img = Image.open(io.BytesIO(restored_raw)).convert("RGB").resize(img.size, Image.Resampling.LANCZOS)
            final_composite = Image.composite(gen_img, img, mask)

            final_buf = io.BytesIO()
            final_composite.save(final_buf, format="JPEG", quality=95)

            return AIRestorationResult(
                success=True,
                restored_bytes=final_buf.getvalue(),
                mask_bytes=mask_bytes,
                provider_name="gemini",
                model_name=self.model,
                confidence=0.89,
                latency_ms=latency,
                pixels_restored_count=damaged_pixels,
                total_pixels=total_pixels
            )

        except httpx.TimeoutException:
            return AIRestorationResult(
                success=False,
                provider_name="gemini",
                model_name=self.model,
                error_message="Gemini API request timed out.",
                latency_ms=round((time.time() - start_time) * 1000, 2)
            )
        except Exception as e:
            clean_err = str(e).replace(str(self.api_key), "[REDACTED]") if self.api_key else str(e)
            return AIRestorationResult(
                success=False,
                provider_name="gemini",
                model_name=self.model,
                error_message=f"Gemini restoration error: {clean_err}",
                latency_ms=round((time.time() - start_time) * 1000, 2)
            )
