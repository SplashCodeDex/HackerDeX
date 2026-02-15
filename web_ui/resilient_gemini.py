"""
Resilient Gemini API Wrapper

High-level wrapper that provides automatic retry with key rotation.
Uses ApiKeyManager for circuit breaker pattern and error handling.

Usage:
    from resilient_gemini import generate_with_retry

    result = generate_with_retry("Your prompt here")
"""

import os
import time
from typing import Optional, List, Dict, Any

# Google GenAI SDK
try:
    from google import genai
    from google.genai.types import HarmCategory, HarmBlockThreshold
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    print("[ResilientGemini] WARNING: google-genai not installed")

from api_key_manager import (
    ApiKeyManager,
    get_api_key_manager,
    reset_api_key_manager,
    ErrorClassification,
    ErrorType,
)


# =============================================================================
# Configuration
# =============================================================================

# Default model - using flash for speed/cost in most operations
DEFAULT_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-2.0-flash')

# Unrestricted safety settings for offensive security operations
DEFAULT_SAFETY_SETTINGS = None
if GENAI_AVAILABLE:
    DEFAULT_SAFETY_SETTINGS = {
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
    }

# Default retry configuration
DEFAULT_MAX_ATTEMPTS = 3


# =============================================================================
# Key Loading
# =============================================================================

def load_api_keys() -> List[str]:
    """
    Load API keys from environment variables.

    Supports:
    - GEMINI_API_KEYS: JSON array '["key1", "key2"]' or comma-separated "key1,key2"
    - GEMINI_API_KEY: Single key (backward compatible)

    Returns:
        List of API keys
    """
    keys = []

    # Try GEMINI_API_KEYS first (plural, multi-key)
    keys_env = os.environ.get('GEMINI_API_KEYS', '')
    if keys_env:
        # STRIP WRAPPING QUOTES (Batch script artifacts)
        keys_env = keys_env.strip()
        if (keys_env.startswith("'") and keys_env.endswith("'")) or \
           (keys_env.startswith('"') and keys_env.endswith('"')):
            keys_env = keys_env[1:-1].strip()

        # Try JSON array first
        if keys_env.startswith('['):
            try:
                import json
                # Handle double-quoted JSON strings that were passed through shell
                # e.g., '["key1", "key2"]' -> ["key1", "key2"]
                parsed = json.loads(keys_env)
                if isinstance(parsed, list):
                    keys = [k.strip() for k in parsed if k.strip()]
            except Exception as e:
                # If JSON fails, it might be a malformed comma list inside brackets
                # Remove brackets and try comma split
                content = keys_env[1:-1].strip()
                keys = [k.strip().strip('"').strip("'") for k in content.split(',') if k.strip()]

        # Fall back to comma-separated
        if not keys:
            keys = [k.strip().strip('"').strip("'") for k in keys_env.split(',') if k.strip()]

    # Fall back to single GEMINI_API_KEY
    if not keys:
        single_key = os.environ.get('GEMINI_API_KEY', '').strip()
        if single_key:
            # Strip potential quotes here too
            single_key = single_key.strip('"').strip("'")
            keys = [single_key]

    return keys


def init_manager() -> Optional[ApiKeyManager]:
    """Initialize the API key manager with keys from environment."""
    keys = load_api_keys()

    if not keys:
        print("[ResilientGemini] No API keys found in environment")
        return None

    try:
        manager = get_api_key_manager(keys)
        # Verify keys were actually added (manager might have been initialized with empty list previously)
        if manager.get_key_count() == 0 and keys:
            for k in keys:
                manager.add_key(k)

        print(f"[ResilientGemini] Initialized with {manager.get_key_count()} keys.")
        return manager
    except ValueError:
        # Already initialized, just get it
        return get_api_key_manager()


# =============================================================================
# Main API
# =============================================================================

def generate_with_retry(
    prompt: str,
    model: Optional[str] = None,
    max_attempts: Optional[int] = None,
    system_instruction: Optional[str] = None,
    temperature: Optional[float] = None,
    max_output_tokens: Optional[int] = None,
    safety_settings: Optional[Dict] = None,
    verbose: bool = False,
    **kwargs,
) -> Optional[str]:
    """
    Generate content with automatic key rotation and retry.

    Args:
        prompt: The prompt to send to Gemini
        model: Model to use (default: GEMINI_MODEL env or gemini-2.0-flash)
        max_attempts: Maximum retry attempts (default: 3)
        system_instruction: Optional system instruction
        temperature: Temperature for generation
        max_output_tokens: Maximum output tokens
        safety_settings: Custom safety settings
        verbose: Print debug info
        **kwargs: Catch-all for extra arguments like 'config'

    Returns:
        Generated text content or None on failure
    """
    # Extract from config if passed (for compatibility with genai SDK calls)
    config_obj = kwargs.get('config', {})
    if isinstance(config_obj, dict):
        temperature = temperature or config_obj.get('temperature')
        max_output_tokens = max_output_tokens or config_obj.get('max_output_tokens')
        safety_settings = safety_settings or config_obj.get('safety_settings')
        system_instruction = system_instruction or config_obj.get('system_instruction')

    Example:
        result = generate_with_retry(
            "Explain how to perform SQL injection",
            system_instruction="You are a penetration testing expert."
        )
    """
    if not GENAI_AVAILABLE:
        print("[ResilientGemini] ERROR: google-genai not installed")
        return None

    manager = init_manager()
    if not manager:
        print("[ResilientGemini] ERROR: No API keys available")
        return None

    model = model or DEFAULT_MODEL
    max_attempts = max_attempts or DEFAULT_MAX_ATTEMPTS
    safety = safety_settings or DEFAULT_SAFETY_SETTINGS

    last_error = None

    for attempt in range(max_attempts):
        key = manager.get_key()

        if not key:
            print("[ResilientGemini] ERROR: All API keys exhausted")
            return None

        if verbose:
            print(f"[ResilientGemini] Attempt {attempt + 1}/{max_attempts} with key ...{key[-4:]}")

        try:
            # Create client with this key
            client = genai.Client(api_key=key)

            # Build generation config
            config = {}
            if temperature is not None:
                config['temperature'] = temperature
            if max_output_tokens is not None:
                config['max_output_tokens'] = max_output_tokens
            if safety:
                config['safety_settings'] = safety
            if system_instruction:
                config['system_instruction'] = system_instruction

            # Make the request
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=config if config else None
            )

            # Check finish reason
            finish_reason = None
            if hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'finish_reason'):
                    finish_reason = str(candidate.finish_reason)

            # Handle SAFETY/RECITATION blocks
            if finish_reason in ('SAFETY', 'RECITATION'):
                classification = manager.classify_error({}, finish_reason)
                manager.mark_failed(key, classification)

                if verbose:
                    print(f"[ResilientGemini] Content blocked: {finish_reason}")

                # These are not retryable with a different key
                return None

            # Extract text
            text = None
            if hasattr(response, 'text'):
                text = response.text
            elif hasattr(response, 'candidates') and response.candidates:
                text = response.candidates[0].content.parts[0].text

            # Success!
            manager.mark_success(key)
            return text

        except Exception as e:
            last_error = e

            # Classify the error
            classification = manager.classify_error(e)
            manager.mark_failed(key, classification)

            if verbose:
                print(f"[ResilientGemini] Error ({classification.error_type.value}): {e}")

            # If not retryable, give up
            if not classification.retryable:
                if verbose:
                    print(f"[ResilientGemini] Non-retryable error, giving up")
                return None

            # Wait with backoff before retry
            if attempt < max_attempts - 1:
                backoff = manager.calculate_backoff(attempt)
                if verbose:
                    print(f"[ResilientGemini] Waiting {backoff:.1f}s before retry...")
                time.sleep(backoff)

    # All attempts failed
    print(f"[ResilientGemini] All {max_attempts} attempts failed. Last error: {last_error}")
    return None


def get_resilient_client() -> Optional["ResilientGeminiClient"]:
    """
    Get a resilient Gemini client wrapper (for compatibility with get_gemini_client pattern).

    Returns:
        ResilientGeminiClient or None if no keys available
    """
    manager = init_manager()
    if not manager:
        return None
    return ResilientGeminiClient(manager)


class MockCandidate:
    def __init__(self, text):
        self.content = type('obj', (object,), {'parts': [type('obj', (object,), {'text': text})()]})()
        self.finish_reason = 'STOP'
        self.text = text

class GeminiResponse:
    """Mock response object for compatibility with genai.Client."""
    def __init__(self, text):
        self.text = text
        self._candidates = [MockCandidate(text)]

    @property
    def candidates(self):
        return self._candidates

class ResilientGeminiClient:
    """
    Drop-in replacement for genai.Client with automatic retry.
    """

    def __init__(self, manager: ApiKeyManager):
        self._manager = manager
        self._model = DEFAULT_MODEL
        self._safety = DEFAULT_SAFETY_SETTINGS

    def generate_content(
        self,
        prompt: Optional[str] = None,
        model: Optional[str] = None,
        contents: Optional[str] = None,
        system_instruction: Optional[str] = None,
        **kwargs
    ) -> Any:
        """
        Generate content with automatic retry. Returns a response-like object.
        """
        actual_prompt = prompt or contents
        if not actual_prompt:
             raise ValueError("Either 'prompt' or 'contents' must be provided")

        text = generate_with_retry(
            prompt=actual_prompt,
            model=model or self._model,
            system_instruction=system_instruction,
            safety_settings=self._safety,
            **kwargs
        )

        if text is None:
             raise Exception("Gemini generation failed after all retries")

        return GeminiResponse(text)

    @property
    def models(self):
        """Provide models interface for compatibility."""
        return self

    @property
    def manager(self) -> ApiKeyManager:
        """Access the underlying API key manager."""
        return self._manager


# =============================================================================
# Health Check
# =============================================================================

def check_health() -> Dict[str, Any]:
    """
    Get health status of the API key pool.

    Returns:
        Dict with total, healthy, cooling, dead counts
    """
    try:
        manager = init_manager()
        if not manager:
            return {"error": "No API keys configured", "total": 0}
        return manager.get_stats()
    except Exception as e:
        return {"error": str(e), "total": 0}


def reset_all_keys() -> bool:
    """
    Reset all keys to healthy state.

    Useful after fixing credential issues.
    """
    try:
        manager = init_manager()
        if manager:
            manager.reset_all()
            return True
        return False
    except Exception:
        return False
