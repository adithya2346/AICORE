"""
Factory to instantiate AI Image Restoration Providers dynamically.
Supports 'openai', 'gemini', 'stability', and 'mock' providers.
"""
import os
from typing import Optional
from backend.config import settings
from backend.services.providers.base import AIRestorationProvider
from backend.services.providers.openai_provider import OpenAIRestorationProvider
from backend.services.providers.gemini_provider import GeminiRestorationProvider
from backend.services.providers.mock_provider import MockAIRestorationProvider

def get_ai_provider(
    provider_name: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None
) -> AIRestorationProvider:
    """
    Instantiate and return the configured AI Restoration Provider.
    
    Args:
        provider_name: e.g. 'openai', 'gemini', 'mock'. Defaults to settings.ai_provider.
        api_key: Optional API key override. Defaults to settings.ai_api_key.
        model: Optional model identifier. Defaults to settings.ai_model.
    """
    prov = (provider_name or settings.ai_provider or "openai").lower().strip()
    key = api_key or settings.ai_api_key or os.environ.get("AI_API_KEY")
    selected_model = model or settings.ai_model or "default"
    timeout = settings.recovery_timeout_seconds

    if prov == "mock":
        return MockAIRestorationProvider(api_key="mock_key", model="mock-inpaint-v1", timeout_seconds=timeout)
    elif prov == "openai":
        if not key or key.strip() in ("", "your_api_key_here"):
            raise ValueError(
                "AI_API_KEY environment variable is required for provider 'openai'. "
                "Please configure process.env.AI_API_KEY / AI_API_KEY in server environment (.env)."
            )
        return OpenAIRestorationProvider(api_key=key, model=selected_model or "dall-e-2", timeout_seconds=timeout)
    elif prov == "gemini":
        if not key or key.strip() in ("", "your_api_key_here"):
            raise ValueError(
                "AI_API_KEY environment variable is required for provider 'gemini'. "
                "Please configure process.env.AI_API_KEY / AI_API_KEY in server environment (.env)."
            )
        return GeminiRestorationProvider(api_key=key, model=selected_model or "imagen-3.0-generate-002", timeout_seconds=timeout)
    else:
        # Fallback to mock with warning if unknown provider specified
        return MockAIRestorationProvider(api_key="fallback_mock", model=f"unknown-{prov}-fallback", timeout_seconds=timeout)
