"""
Gemini Configuration - Enhanced with Resilient API Key Rotation

This module provides both legacy single-key and new multi-key resilient clients.

Usage:
    # Legacy (single key, backward compatible)
    client = get_gemini_client()

    # New (multi-key with automatic rotation and retry)
    from resilient_gemini import generate_with_retry
    result = generate_with_retry("Your prompt")

    # Or use the resilient client wrapper
    client = get_resilient_gemini_client()
"""

import os
from google import genai
from google.genai.types import HarmCategory, HarmBlockThreshold

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# =============================================================================
# API Keys Configuration
# =============================================================================

# Single key (legacy, backward compatible)
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')

# Multi-key support: use GEMINI_API_KEYS environment variable
# Format: JSON array '["key1", "key2"]' or comma-separated "key1,key2"
GEMINI_API_KEYS = os.environ.get('GEMINI_API_KEYS', '')

# Default model
GEMINI_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-2.0-flash')

# =============================================================================
# Safety Configuration: Unrestricted for Offensive Operations
# =============================================================================

SAFETY_SETTINGS = {
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}


# =============================================================================
# Legacy Client (Single Key)
# =============================================================================

def get_gemini_client():
    """
    Get configured Gemini client with unrestricted safety settings.

    DEPRECATED: For new code, use get_resilient_gemini_client() instead.
    This function remains for backward compatibility with existing code.

    Returns:
        genai.Client or None if no API key configured
    """
    if not GEMINI_API_KEY:
        return None
    try:
        return genai.Client(api_key=GEMINI_API_KEY)
    except Exception:
        return None


# =============================================================================
# Resilient Client (Multi-Key with Rotation)
# =============================================================================

def get_resilient_gemini_client():
    """
    Get resilient Gemini client with automatic key rotation and retry.

    This client will:
    - Rotate through multiple API keys on failure
    - Implement circuit breaker pattern
    - Automatically retry with exponential backoff
    - Mark dead keys for permanent exclusion

    Requires GEMINI_API_KEYS environment variable (JSON array or comma-separated).
    Falls back to GEMINI_API_KEY if GEMINI_API_KEYS not set.

    Returns:
        ResilientGeminiClient or None if no keys available
    """
    try:
        from resilient_gemini import get_resilient_client
        return get_resilient_client()
    except ImportError:
        print("[GeminiConfig] WARNING: resilient_gemini not available, falling back to legacy client")
        return get_gemini_client()
    except Exception as e:
        print(f"[GeminiConfig] ERROR: {e}")
        return None


# =============================================================================
# Convenience Function for Direct Generation
# =============================================================================

def generate_content(
    prompt: str,
    system_instruction: str = None,
    use_resilient: bool = True,
    **kwargs
):
    """
    Generate content using Gemini with optional resilient retry.

    Args:
        prompt: The prompt to send
        system_instruction: Optional system instruction
        use_resilient: Use resilient client with retry (default True)
        **kwargs: Additional arguments passed to generate

    Returns:
        Generated text or None on failure
    """
    if use_resilient:
        try:
            from resilient_gemini import generate_with_retry
            return generate_with_retry(
                prompt=prompt,
                system_instruction=system_instruction,
                **kwargs
            )
        except ImportError:
            pass

    # Fall back to legacy single-key client
    client = get_gemini_client()
    if not client:
        return None

    try:
        config = {'safety_settings': SAFETY_SETTINGS}
        if system_instruction:
            config['system_instruction'] = system_instruction

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=config
        )

        if hasattr(response, 'text'):
            return response.text
        return None
    except Exception as e:
        print(f"[GeminiConfig] Generation error: {e}")
        return None
