"""
API Key Manager - Circuit Breaker Pattern for Gemini API

Implements multi-key rotation with:
- Circuit breaker states (CLOSED, OPEN, HALF_OPEN, DEAD)
- Error classification for Gemini-specific errors
- Exponential backoff with jitter
- Retry-After header parsing
- State persistence via JSON file

Reference: API-Rotation-system.md
"""

import os
import re
import json
import time
import random
import threading
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path


# =============================================================================
# Enums & Types
# =============================================================================

class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "CLOSED"       # Normal operation
    OPEN = "OPEN"           # Key blocked, cooling down
    HALF_OPEN = "HALF_OPEN" # Testing if key recovered
    DEAD = "DEAD"           # Permanently invalid (403)


class ErrorType(Enum):
    """Error classification types"""
    QUOTA = "QUOTA"           # 429 - Rate limit
    TRANSIENT = "TRANSIENT"   # 500/503/504 - Retry with backoff
    AUTH = "AUTH"             # 403 - Key is dead
    BAD_REQUEST = "BAD_REQUEST"  # 400 - Don't retry, fix request
    SAFETY = "SAFETY"         # finishReason: SAFETY - Not key's fault
    RECITATION = "RECITATION" # finishReason: RECITATION - Not key's fault
    NOT_FOUND = "NOT_FOUND"   # 404 - Resource missing
    CANCELLED = "CANCELLED"   # 499 - Client cancelled
    UNKNOWN = "UNKNOWN"       # Catch-all


@dataclass
class ErrorClassification:
    """Result of error classification"""
    error_type: ErrorType
    retryable: bool
    cooldown_ms: int
    mark_key_failed: bool
    mark_key_dead: bool
    message: str = ""


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class ApiKeyManagerConfig:
    """Configuration options"""
    max_consecutive_failures: int = 5
    cooldown_transient_ms: int = 60 * 1000         # 1 minute
    cooldown_quota_ms: int = 5 * 60 * 1000         # 5 minutes
    cooldown_quota_daily_ms: int = 60 * 60 * 1000  # 1 hour
    half_open_test_delay_ms: int = 60 * 1000       # 1 minute
    max_backoff_ms: int = 64 * 1000                # 64 seconds
    base_backoff_ms: int = 1000                    # 1 second
    state_file: str = "api_key_state.json"


# =============================================================================
# Error Patterns
# =============================================================================

ERROR_PATTERNS = {
    "quota": re.compile(
        r"429|quota|exhausted|resource.?exhausted|too.?many.?requests|rate.?limit|RESOURCE_EXHAUSTED",
        re.IGNORECASE
    ),
    "auth": re.compile(
        r"403|401|permission.?denied|invalid.?api.?key|unauthorized|unauthenticated|PERMISSION_DENIED",
        re.IGNORECASE
    ),
    "safety": re.compile(
        r"safety|blocked|recitation|harmful|HARM_CATEGORY",
        re.IGNORECASE
    ),
    "transient": re.compile(
        r"500|502|503|504|internal|unavailable|deadline|timeout|overloaded|INTERNAL|UNAVAILABLE",
        re.IGNORECASE
    ),
    "bad_request": re.compile(
        r"400|invalid.?argument|failed.?precondition|malformed|INVALID_ARGUMENT",
        re.IGNORECASE
    ),
    "not_found": re.compile(
        r"404|not.?found|NOT_FOUND",
        re.IGNORECASE
    ),
}


# =============================================================================
# Key State
# =============================================================================

@dataclass
class KeyState:
    """State of a single API key"""
    key: str
    fail_count: int = 0
    failed_at: Optional[float] = None
    is_quota_error: bool = False
    circuit_state: CircuitState = CircuitState.CLOSED
    last_used: float = 0.0
    success_count: int = 0
    total_requests: int = 0
    half_open_test_time: Optional[float] = None
    custom_cooldown_ms: Optional[int] = None
    last_error_type: Optional[ErrorType] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for persistence"""
        return {
            "fail_count": self.fail_count,
            "failed_at": self.failed_at,
            "is_quota_error": self.is_quota_error,
            "circuit_state": self.circuit_state.value,
            "last_used": self.last_used,
            "success_count": self.success_count,
            "total_requests": self.total_requests,
            "half_open_test_time": self.half_open_test_time,
            "custom_cooldown_ms": self.custom_cooldown_ms,
            "last_error_type": self.last_error_type.value if self.last_error_type else None,
        }

    @classmethod
    def from_dict(cls, key: str, data: Dict[str, Any]) -> "KeyState":
        """Deserialize from persistence"""
        state = cls(key=key)
        state.fail_count = data.get("fail_count", 0)
        state.failed_at = data.get("failed_at")
        state.is_quota_error = data.get("is_quota_error", False)
        state.circuit_state = CircuitState(data.get("circuit_state", "CLOSED"))
        state.last_used = data.get("last_used", 0.0)
        state.success_count = data.get("success_count", 0)
        state.total_requests = data.get("total_requests", 0)
        state.half_open_test_time = data.get("half_open_test_time")
        state.custom_cooldown_ms = data.get("custom_cooldown_ms")
        error_type = data.get("last_error_type")
        state.last_error_type = ErrorType(error_type) if error_type else None
        return state


# =============================================================================
# Main Class
# =============================================================================

class ApiKeyManager:
    """
    Multi-key API rotation manager with circuit breaker pattern.

    Features:
    - Automatic key rotation on failure
    - Circuit breaker to prevent hammering dead keys
    - Error classification (quota, auth, transient, safety)
    - Exponential backoff with jitter
    - State persistence across restarts
    """

    def __init__(
        self,
        keys: List[str],
        config: Optional[ApiKeyManagerConfig] = None,
        state_dir: Optional[str] = None
    ):
        self.config = config or ApiKeyManagerConfig()
        self._lock = threading.Lock()

        # Determine state file path
        if state_dir:
            self._state_file = Path(state_dir) / self.config.state_file
        else:
            self._state_file = Path(__file__).parent / self.config.state_file

        # Initialize keys
        self._keys: Dict[str, KeyState] = {}
        for key in keys:
            if key and key.strip():
                self._keys[key] = KeyState(key=key)

        # Load persisted state
        self._load_state()

        # Callbacks
        self._on_key_death: Optional[Callable[[str], None]] = None
        self._on_all_exhausted: Optional[Callable[[], None]] = None

    # =========================================================================
    # Event Callbacks
    # =========================================================================

    def set_on_key_death(self, callback: Callable[[str], None]) -> None:
        """Set callback when a key is permanently marked as dead."""
        self._on_key_death = callback

    def set_on_all_exhausted(self, callback: Callable[[], None]) -> None:
        """Set callback when all keys are exhausted."""
        self._on_all_exhausted = callback

    # =========================================================================
    # Error Classification
    # =========================================================================

    def classify_error(
        self,
        error: Any,
        finish_reason: Optional[str] = None
    ) -> ErrorClassification:
        """
        Classify an error to determine handling strategy.

        Args:
            error: Exception or error dict from API
            finish_reason: Optional finishReason from Gemini response

        Returns:
            ErrorClassification with retry/cooldown info
        """
        # Get status code and message
        status = None
        message = ""

        if hasattr(error, 'status_code'):
            status = error.status_code
        elif hasattr(error, 'code'):
            status = error.code
        elif isinstance(error, dict):
            status = error.get('status') or error.get('code')

        if hasattr(error, 'message'):
            message = str(error.message)
        elif isinstance(error, dict):
            message = str(error.get('message', error.get('error', '')))
        else:
            message = str(error)

        # 1. Check finishReason first (for 200 responses with content issues)
        if finish_reason == "SAFETY":
            return ErrorClassification(
                error_type=ErrorType.SAFETY,
                retryable=False,
                cooldown_ms=0,
                mark_key_failed=False,
                mark_key_dead=False,
                message="Content blocked by safety filters"
            )
        if finish_reason == "RECITATION":
            return ErrorClassification(
                error_type=ErrorType.RECITATION,
                retryable=False,
                cooldown_ms=0,
                mark_key_failed=False,
                mark_key_dead=False,
                message="Content resembles copyrighted material"
            )

        # 2. Auth errors (key death)
        if status in (401, 403) or ERROR_PATTERNS["auth"].search(message):
            return ErrorClassification(
                error_type=ErrorType.AUTH,
                retryable=False,
                cooldown_ms=float('inf'),
                mark_key_failed=True,
                mark_key_dead=True,
                message="API key is invalid or lacks permissions"
            )

        # 3. Quota/rate limit
        if status == 429 or ERROR_PATTERNS["quota"].search(message):
            retry_after = self._parse_retry_after(error)
            return ErrorClassification(
                error_type=ErrorType.QUOTA,
                retryable=True,
                cooldown_ms=retry_after or self.config.cooldown_quota_ms,
                mark_key_failed=True,
                mark_key_dead=False,
                message="Rate limit or quota exceeded"
            )

        # 4. Bad request (don't retry)
        if status == 400 or ERROR_PATTERNS["bad_request"].search(message):
            return ErrorClassification(
                error_type=ErrorType.BAD_REQUEST,
                retryable=False,
                cooldown_ms=0,
                mark_key_failed=False,
                mark_key_dead=False,
                message="Invalid request - check parameters"
            )

        # 5. Not found
        if status == 404 or ERROR_PATTERNS["not_found"].search(message):
            return ErrorClassification(
                error_type=ErrorType.NOT_FOUND,
                retryable=False,
                cooldown_ms=0,
                mark_key_failed=False,
                mark_key_dead=False,
                message="Resource not found"
            )

        # 6. Client cancelled
        if status == 499:
            return ErrorClassification(
                error_type=ErrorType.CANCELLED,
                retryable=False,
                cooldown_ms=0,
                mark_key_failed=False,
                mark_key_dead=False,
                message="Request cancelled"
            )

        # 7. Transient errors
        if status in (500, 502, 503, 504) or ERROR_PATTERNS["transient"].search(message):
            return ErrorClassification(
                error_type=ErrorType.TRANSIENT,
                retryable=True,
                cooldown_ms=self.config.cooldown_transient_ms,
                mark_key_failed=True,
                mark_key_dead=False,
                message="Transient server error"
            )

        # 8. Unknown - default to retryable
        return ErrorClassification(
            error_type=ErrorType.UNKNOWN,
            retryable=True,
            cooldown_ms=self.config.cooldown_transient_ms,
            mark_key_failed=True,
            mark_key_dead=False,
            message="Unknown error"
        )

    def _parse_retry_after(self, error: Any) -> Optional[int]:
        """Parse Retry-After header from error response."""
        retry_after = None

        # Try different ways to get header
        if hasattr(error, 'headers'):
            retry_after = error.headers.get('Retry-After') or error.headers.get('retry-after')
        elif hasattr(error, 'response') and hasattr(error.response, 'headers'):
            retry_after = error.response.headers.get('Retry-After')
        elif isinstance(error, dict):
            retry_after = error.get('retry_after') or error.get('retryAfter')

        if not retry_after:
            return None

        # Parse as seconds
        try:
            return int(retry_after) * 1000
        except ValueError:
            pass

        # Parse as HTTP date
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(str(retry_after))
            return max(0, int((dt.timestamp() - time.time()) * 1000))
        except Exception:
            pass

        return None

    # =========================================================================
    # Key Selection
    # =========================================================================

    def _is_on_cooldown(self, key_state: KeyState) -> bool:
        """Check if a key is currently on cooldown."""
        if key_state.circuit_state == CircuitState.DEAD:
            return True

        now = time.time() * 1000  # ms

        if key_state.circuit_state == CircuitState.OPEN:
            if key_state.half_open_test_time and now >= key_state.half_open_test_time:
                key_state.circuit_state = CircuitState.HALF_OPEN
                return False
            return True

        # Check custom cooldown
        if key_state.failed_at and key_state.custom_cooldown_ms:
            if now - (key_state.failed_at * 1000) < key_state.custom_cooldown_ms:
                return True

        # Standard cooldown
        if key_state.failed_at:
            cooldown = self.config.cooldown_quota_ms if key_state.is_quota_error else self.config.cooldown_transient_ms
            if now - (key_state.failed_at * 1000) < cooldown:
                return True

        return False

    def get_key(self) -> Optional[str]:
        """
        Get the best available API key.

        Priority:
        1. Exclude DEAD keys
        2. Exclude keys on cooldown
        3. Prefer keys with fewer failures
        4. Prefer least recently used (LRU)

        Returns:
            API key string or None if all exhausted
        """
        with self._lock:
            # Filter out dead and cooling keys
            candidates = [
                k for k in self._keys.values()
                if k.circuit_state != CircuitState.DEAD and not self._is_on_cooldown(k)
            ]

            if not candidates:
                # Fallback: return oldest failed key (excluding DEAD)
                non_dead = [k for k in self._keys.values() if k.circuit_state != CircuitState.DEAD]
                if not non_dead:
                    if self._on_all_exhausted:
                        self._on_all_exhausted()
                    return None

                # Sort by oldest failure
                non_dead.sort(key=lambda k: k.failed_at or 0)
                return non_dead[0].key

            # Sort: fewer failures first, then LRU
            candidates.sort(key=lambda k: (k.fail_count, k.last_used))

            selected = candidates[0]
            selected.last_used = time.time()
            self._save_state()

            return selected.key

    def get_key_count(self) -> int:
        """Get count of healthy (non-DEAD) keys."""
        with self._lock:
            return sum(1 for k in self._keys.values() if k.circuit_state != CircuitState.DEAD)

    # =========================================================================
    # Feedback Loop
    # =========================================================================

    def mark_success(self, key: str) -> None:
        """Mark a key as successful - resets failure state."""
        with self._lock:
            if key not in self._keys:
                return

            k = self._keys[key]

            if k.circuit_state not in (CircuitState.CLOSED, CircuitState.DEAD):
                print(f"[ApiKeyManager] Key recovered: ...{key[-4:]}")

            k.circuit_state = CircuitState.CLOSED
            k.fail_count = 0
            k.failed_at = None
            k.is_quota_error = False
            k.custom_cooldown_ms = None
            k.last_error_type = None
            k.success_count += 1
            k.total_requests += 1

            self._save_state()

    def mark_failed(self, key: str, classification: ErrorClassification) -> None:
        """Mark a key as failed with error classification."""
        with self._lock:
            if key not in self._keys:
                return

            k = self._keys[key]

            # Don't modify DEAD keys
            if k.circuit_state == CircuitState.DEAD:
                return

            # If this error shouldn't mark key as failed, just log
            if not classification.mark_key_failed:
                k.total_requests += 1
                k.last_error_type = classification.error_type
                self._save_state()
                return

            k.failed_at = time.time()
            k.fail_count += 1
            k.total_requests += 1
            k.is_quota_error = classification.error_type == ErrorType.QUOTA
            k.custom_cooldown_ms = classification.cooldown_ms if classification.cooldown_ms != float('inf') else None
            k.last_error_type = classification.error_type

            # Permanent death for auth errors
            if classification.mark_key_dead:
                k.circuit_state = CircuitState.DEAD
                print(f"[ApiKeyManager] KEY DEAD: ...{key[-4:]} - Removed from rotation")
                if self._on_key_death:
                    self._on_key_death(key)
                self._save_state()
                return

            # State transitions
            if k.circuit_state == CircuitState.HALF_OPEN:
                k.circuit_state = CircuitState.OPEN
                k.half_open_test_time = (time.time() * 1000) + self.config.half_open_test_delay_ms
            elif k.fail_count >= self.config.max_consecutive_failures or classification.error_type == ErrorType.QUOTA:
                k.circuit_state = CircuitState.OPEN
                k.half_open_test_time = (time.time() * 1000) + (classification.cooldown_ms or self.config.half_open_test_delay_ms)

            self._save_state()

    # =========================================================================
    # Backoff Calculation
    # =========================================================================

    def calculate_backoff(self, attempt: int) -> float:
        """
        Calculate exponential backoff delay with jitter.

        Returns:
            Delay in seconds
        """
        exponential = self.config.base_backoff_ms * (2 ** attempt)
        capped = min(exponential, self.config.max_backoff_ms)
        jitter = random.random() * 1000
        return (capped + jitter) / 1000  # Convert to seconds

    # =========================================================================
    # Health Statistics
    # =========================================================================

    def get_stats(self) -> Dict[str, int]:
        """Get health statistics for all keys."""
        with self._lock:
            total = len(self._keys)
            dead = sum(1 for k in self._keys.values() if k.circuit_state == CircuitState.DEAD)
            cooling = sum(1 for k in self._keys.values() if k.circuit_state in (CircuitState.OPEN, CircuitState.HALF_OPEN))
            healthy = total - dead - cooling

            return {
                "total": total,
                "healthy": healthy,
                "cooling": cooling,
                "dead": dead,
            }

    def get_all_key_states(self) -> List[Dict[str, Any]]:
        """Get all key states for debugging/monitoring."""
        with self._lock:
            return [
                {"key": f"...{k.key[-4:]}", **k.to_dict()}
                for k in self._keys.values()
            ]

    # =========================================================================
    # Key Management
    # =========================================================================

    def add_key(self, key: str) -> None:
        """Add a new key to the pool."""
        with self._lock:
            if key in self._keys:
                print(f"[ApiKeyManager] Key already exists: ...{key[-4:]}")
                return

            self._keys[key] = KeyState(key=key)
            self._save_state()
            print(f"[ApiKeyManager] Key added: ...{key[-4:]}")

    def remove_key(self, key: str) -> bool:
        """Remove a key from the pool."""
        with self._lock:
            if key not in self._keys:
                return False

            del self._keys[key]
            self._save_state()
            print(f"[ApiKeyManager] Key removed: ...{key[-4:]}")
            return True

    def revive_key(self, key: str) -> bool:
        """Revive a DEAD key (e.g., after fixing credentials)."""
        with self._lock:
            if key not in self._keys:
                return False

            k = self._keys[key]
            k.circuit_state = CircuitState.CLOSED
            k.fail_count = 0
            k.failed_at = None
            k.is_quota_error = False
            k.custom_cooldown_ms = None
            k.last_error_type = None

            self._save_state()
            print(f"[ApiKeyManager] Key revived: ...{key[-4:]}")
            return True

    def reset_all(self) -> None:
        """Reset all keys to healthy state."""
        with self._lock:
            for k in self._keys.values():
                k.circuit_state = CircuitState.CLOSED
                k.fail_count = 0
                k.failed_at = None
                k.is_quota_error = False
                k.custom_cooldown_ms = None
                k.last_error_type = None

            self._save_state()
            print("[ApiKeyManager] All keys reset")

    # =========================================================================
    # Persistence
    # =========================================================================

    def _save_state(self) -> None:
        """Save state to JSON file."""
        try:
            state = {k: v.to_dict() for k, v in self._keys.items()}
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"[ApiKeyManager] Failed to save state: {e}")

    def _load_state(self) -> None:
        """Load state from JSON file."""
        try:
            if not self._state_file.exists():
                return

            with open(self._state_file, 'r') as f:
                data = json.load(f)

            for key, state_data in data.items():
                if key in self._keys:
                    self._keys[key] = KeyState.from_dict(key, state_data)
        except Exception as e:
            print(f"[ApiKeyManager] Failed to load state: {e}")

    def clear_persisted_state(self) -> None:
        """Delete the state file."""
        try:
            if self._state_file.exists():
                self._state_file.unlink()
                print("[ApiKeyManager] State file cleared")
        except Exception as e:
            print(f"[ApiKeyManager] Failed to clear state: {e}")


# =============================================================================
# Singleton Access
# =============================================================================

_instance: Optional[ApiKeyManager] = None
_instance_lock = threading.Lock()


def get_api_key_manager(keys: Optional[List[str]] = None) -> ApiKeyManager:
    """
    Get or create the singleton ApiKeyManager instance.

    Args:
        keys: List of API keys (required on first call)

    Returns:
        ApiKeyManager instance
    """
    global _instance

    with _instance_lock:
        if _instance is None:
            if not keys:
                raise ValueError("ApiKeyManager not initialized. Provide keys on first call.")
            _instance = ApiKeyManager(keys)
        return _instance


def reset_api_key_manager() -> None:
    """Reset the singleton (for testing)."""
    global _instance
    with _instance_lock:
        _instance = None
