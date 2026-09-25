"""
OpenAI DALL-E / Image Inpainting Restoration Provider.
Secured: API keys are read from environment, never logged, and never sent to clients.
"""
import io
import time
import base64
from typing import Optional
import httpx
from PIL import Image
from backend.services.providers.base import AIRestorationProvider, AIRestorationResult

class OpenAIRestorationProvider(AIRestorationProvider):
    """
    OpenAI DALL-E 2 / Inpainting Adapter.
    Uses the /v1/images/edits endpoint to inpaint damaged regions.
    """
    API_URL = "https://api.openai.com/v1/images/edits"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-image-1",
        timeout_seconds: int = 30
    ):
        super().__init__(api_key=api_key, model=model or "gpt-image-1", timeout_seconds=timeout_seconds)

    @property
    def provider_name(self) -> str:
        return "openai"

    def restore_image(
        self,
        original_image: Optional[Image.Image] = None,
        damage_mask: Optional[Image.Image] = None,
        image_bytes: Optional[bytes] = None,
        mask_bytes: Optional[bytes] = None,
        prompt: Optional[str] = None
    ) -> AIRestorationResult:
        start_time = time.time()
        
        # Security validation: Never proceed without key
        if not self.api_key or self.api_key.strip() in ("", "your_api_key_here"):
            return AIRestorationResult(
                success=False,
                provider_name="openai",
                model_name=self.model,
                error_message="Missing OpenAI API key. Configure AI_API_KEY in server environment.",
                latency_ms=0.0
            )

        try:
            # Resolve image
            if original_image is not None:
                img = original_image.convert("RGBA")
            elif image_bytes is not None:
                img = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
            else:
                raise ValueError("Neither original_image nor image_bytes provided.")

            orig_size = img.size
            total_pixels = orig_size[0] * orig_size[1]

            # Resolve mask
            if damage_mask is not None:
                mask = damage_mask.convert("L")
            elif mask_bytes is not None:
                mask = Image.open(io.BytesIO(mask_bytes)).convert("L")
            else:
                mask = Image.new("L", orig_size, 255)

            if mask.size != orig_size:
                mask = mask.resize(orig_size, Image.Resampling.NEAREST)

            # Count damaged pixels
            mask_data = mask.getdata()
            damaged_pixels = sum(1 for p in mask_data if p > 128)

            # OpenAI expects square PNG <= 1024x1024 and transparency for inpainting
            target_dim = 1024 if max(orig_size) > 512 else (512 if max(orig_size) > 256 else 256)
            
            # Prepare square canvas
            square_img = Image.new("RGBA", (target_dim, target_dim), (0, 0, 0, 0))
            scaled_img = img.resize((target_dim, target_dim), Image.Resampling.LANCZOS)
            square_img.paste(scaled_img, (0, 0))

            # Prepare transparent mask for OpenAI: where mask is white (damaged), alpha is 0 (transparent)
            scaled_mask = mask.resize((target_dim, target_dim), Image.Resampling.NEAREST)
            
            mask_rgba = Image.new("RGBA", (target_dim, target_dim), (255, 255, 255, 0))
            for x in range(target_dim):
                for y in range(target_dim):
                    if scaled_mask.getpixel((x, y)) > 128:
                        # Damaged area: make transparent so DALL-E edits it
                        mask_rgba.putpixel((x, y), (0, 0, 0, 0))
                    else:
                        # Intact area: keep opaque
                        mask_rgba.putpixel((x, y), (0, 0, 0, 255))

            img_buf = io.BytesIO()
            square_img.save(img_buf, format="PNG")
            img_png = img_buf.getvalue()

            mask_buf = io.BytesIO()
            mask_rgba.save(mask_buf, format="PNG")
            mask_png = mask_buf.getvalue()

            headers = {
                "Authorization": f"Bearer {self.api_key}"
            }
            # Use gpt-image-1 by default
            chosen_model = self.model if self.model not in ("dall-e-2", "default") else "gpt-image-1"
            data = {
                "model": chosen_model,
                "prompt": prompt or "Restore missing damaged areas of this photograph seamlessly matching surrounding texture and colors accurately",
                "n": "1",
                "size": f"{target_dim}x{target_dim}"
            }
            files = {
                "image": ("image.png", img_png, "image/png"),
                "mask": ("mask.png", mask_png, "image/png")
            }

            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(self.API_URL, headers=headers, data=data, files=files)

            latency = round((time.time() - start_time) * 1000, 2)

            if resp.status_code == 401:
                return AIRestorationResult(
                    success=False,
                    provider_name="openai",
                    model_name=chosen_model,
                    error_message="Authentication failed: Invalid OpenAI API Key.",
                    latency_ms=latency
                )
            elif resp.status_code == 429:
                err_data = resp.json().get("error", {})
                err_msg = err_data.get("message", "OpenAI rate limit or credit quota exceeded.")
                return AIRestorationResult(
                    success=False,
                    provider_name="openai",
                    model_name=chosen_model,
                    error_message=f"OpenAI Quota/Rate Limit: {err_msg}",
                    latency_ms=latency
                )
            elif resp.status_code != 200:
                err_text = resp.text[:300]
                return AIRestorationResult(
                    success=False,
                    provider_name="openai",
                    model_name=chosen_model,
                    error_message=f"OpenAI API Error ({resp.status_code}): {err_text}",
                    latency_ms=latency
                )

            res_json = resp.json()
            data_item = res_json.get("data", [{}])[0]
            if "b64_json" in data_item:
                generated_bytes = base64.b64decode(data_item["b64_json"])
            elif "url" in data_item:
                with httpx.Client(timeout=20) as img_client:
                    img_resp = img_client.get(data_item["url"])
                    generated_bytes = img_resp.content
            else:
                return AIRestorationResult(
                    success=False,
                    provider_name="openai",
                    model_name=chosen_model,
                    error_message="OpenAI response did not include image bytes or URL.",
                    latency_ms=latency
                )

            # Resize generated image back to original dimensions and composite strictly over mask
            gen_img = Image.open(io.BytesIO(generated_bytes)).convert("RGB").resize(orig_size, Image.Resampling.LANCZOS)
            final_composite = Image.composite(gen_img, img.convert("RGB"), mask)

            final_buf = io.BytesIO()
            final_composite.save(final_buf, format="JPEG", quality=95)

            return AIRestorationResult(
                success=True,
                restored_bytes=final_buf.getvalue(),
                mask_bytes=mask_bytes,
                provider_name="openai",
                model_name=chosen_model,
                confidence=0.91,
                latency_ms=latency,
                pixels_restored_count=damaged_pixels,
                total_pixels=total_pixels
            )

        except httpx.TimeoutException:
            return AIRestorationResult(
                success=False,
                provider_name="openai",
                model_name=self.model,
                error_message="OpenAI API request timed out.",
                latency_ms=round((time.time() - start_time) * 1000, 2)
            )
        except Exception as e:
            # Never leak api_key in error
            clean_err = str(e).replace(str(self.api_key), "[REDACTED]") if self.api_key else str(e)
            return AIRestorationResult(
                success=False,
                provider_name="openai",
                model_name=self.model,
                error_message=f"Restoration error: {clean_err}",
                latency_ms=round((time.time() - start_time) * 1000, 2)
            )
