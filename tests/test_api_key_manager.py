"""
Unit Tests for ApiKeyManager

Tests cover:
- Error classification for all error types
- Circuit breaker state transitions
- Key rotation priority logic
- State persistence
- Backoff calculation
"""

import os
import sys
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

# Add web_ui to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from web_ui.api_key_manager import (
    ApiKeyManager,
    ApiKeyManagerConfig,
    CircuitState,
    ErrorType,
    ErrorClassification,
    KeyState,
    get_api_key_manager,
    reset_api_key_manager,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_state_dir():
    """Create a temporary directory for state files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def manager(temp_state_dir):
    """Create a fresh manager for each test."""
    reset_api_key_manager()
    return ApiKeyManager(
        keys=['key1', 'key2', 'key3'],
        state_dir=temp_state_dir
    )


# =============================================================================
# Error Classification Tests
# =============================================================================

class TestErrorClassification:
    """Tests for classify_error() method."""

    def test_classify_429_as_quota(self, manager):
        """429 status should be classified as QUOTA."""
        result = manager.classify_error({'status': 429})
        assert result.error_type == ErrorType.QUOTA
        assert result.retryable is True
        assert result.mark_key_failed is True
        assert result.mark_key_dead is False

    def test_classify_quota_message(self, manager):
        """Message containing 'quota exhausted' should be QUOTA."""
        result = manager.classify_error({'message': 'Quota exhausted for this API key'})
        assert result.error_type == ErrorType.QUOTA

    def test_classify_resource_exhausted(self, manager):
        """RESOURCE_EXHAUSTED should be QUOTA."""
        result = manager.classify_error({'message': 'RESOURCE_EXHAUSTED: Rate limit exceeded'})
        assert result.error_type == ErrorType.QUOTA

    def test_classify_403_as_auth(self, manager):
        """403 status should be classified as AUTH (dead key)."""
        result = manager.classify_error({'status': 403})
        assert result.error_type == ErrorType.AUTH
        assert result.retryable is False
        assert result.mark_key_failed is True
        assert result.mark_key_dead is True

    def test_classify_401_as_auth(self, manager):
        """401 status should be classified as AUTH."""
        result = manager.classify_error({'status': 401})
        assert result.error_type == ErrorType.AUTH
        assert result.mark_key_dead is True

    def test_classify_invalid_api_key(self, manager):
        """'Invalid API key' message should be AUTH."""
        result = manager.classify_error({'message': 'Invalid API key provided'})
        assert result.error_type == ErrorType.AUTH

    def test_classify_safety_finish_reason(self, manager):
        """finishReason SAFETY should not mark key as failed."""
        result = manager.classify_error({}, finish_reason='SAFETY')
        assert result.error_type == ErrorType.SAFETY
        assert result.retryable is False
        assert result.mark_key_failed is False
        assert result.mark_key_dead is False

    def test_classify_recitation_finish_reason(self, manager):
        """finishReason RECITATION should not mark key as failed."""
        result = manager.classify_error({}, finish_reason='RECITATION')
        assert result.error_type == ErrorType.RECITATION
        assert result.retryable is False
        assert result.mark_key_failed is False

    def test_classify_500_as_transient(self, manager):
        """500 status should be TRANSIENT."""
        result = manager.classify_error({'status': 500})
        assert result.error_type == ErrorType.TRANSIENT
        assert result.retryable is True

    def test_classify_503_as_transient(self, manager):
        """503 status should be TRANSIENT."""
        result = manager.classify_error({'status': 503})
        assert result.error_type == ErrorType.TRANSIENT

    def test_classify_unavailable(self, manager):
        """UNAVAILABLE message should be TRANSIENT."""
        result = manager.classify_error({'message': 'Service UNAVAILABLE temporarily'})
        assert result.error_type == ErrorType.TRANSIENT

    def test_classify_400_as_bad_request(self, manager):
        """400 status should be BAD_REQUEST."""
        result = manager.classify_error({'status': 400})
        assert result.error_type == ErrorType.BAD_REQUEST
        assert result.retryable is False
        assert result.mark_key_failed is False

    def test_classify_404_as_not_found(self, manager):
        """404 status should be NOT_FOUND."""
        result = manager.classify_error({'status': 404})
        assert result.error_type == ErrorType.NOT_FOUND
        assert result.retryable is False


# =============================================================================
# Circuit Breaker Tests
# =============================================================================

class TestCircuitBreaker:
    """Tests for circuit breaker state transitions."""

    def test_initial_state_is_closed(self, manager):
        """All keys should start in CLOSED state."""
        for key_state in manager.get_all_key_states():
            assert key_state['circuit_state'] == 'CLOSED'

    def test_transition_to_open_on_quota(self, manager):
        """QUOTA error should immediately transition to OPEN."""
        classification = ErrorClassification(
            error_type=ErrorType.QUOTA,
            retryable=True,
            cooldown_ms=5000,
            mark_key_failed=True,
            mark_key_dead=False
        )

        manager.mark_failed('key1', classification)

        states = {s['key']: s for s in manager.get_all_key_states()}
        assert states['...key1']['circuit_state'] == 'OPEN'

    def test_transition_to_dead_on_auth(self, manager):
        """AUTH error should transition to DEAD."""
        classification = ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        )

        manager.mark_failed('key1', classification)

        states = {s['key']: s for s in manager.get_all_key_states()}
        assert states['...key1']['circuit_state'] == 'DEAD'

    def test_transition_to_open_on_max_failures(self, manager):
        """Should transition to OPEN after max consecutive failures."""
        classification = ErrorClassification(
            error_type=ErrorType.TRANSIENT,
            retryable=True,
            cooldown_ms=1000,
            mark_key_failed=True,
            mark_key_dead=False
        )

        # Fail 5 times (default max)
        for _ in range(5):
            manager.mark_failed('key1', classification)

        states = {s['key']: s for s in manager.get_all_key_states()}
        assert states['...key1']['circuit_state'] == 'OPEN'

    def test_success_resets_to_closed(self, manager):
        """Success should reset circuit to CLOSED."""
        # First put key in OPEN state
        classification = ErrorClassification(
            error_type=ErrorType.QUOTA,
            retryable=True,
            cooldown_ms=0,  # No cooldown for test
            mark_key_failed=True,
            mark_key_dead=False
        )
        manager.mark_failed('key1', classification)

        # Then mark success
        manager.mark_success('key1')

        states = {s['key']: s for s in manager.get_all_key_states()}
        assert states['...key1']['circuit_state'] == 'CLOSED'
        assert states['...key1']['fail_count'] == 0

    def test_dead_keys_not_modified(self, manager):
        """DEAD keys should not be modified by further failures."""
        # Kill the key
        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        ))

        # Try to modify it
        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.TRANSIENT,
            retryable=True,
            cooldown_ms=1000,
            mark_key_failed=True,
            mark_key_dead=False
        ))

        states = {s['key']: s for s in manager.get_all_key_states()}
        assert states['...key1']['circuit_state'] == 'DEAD'


# =============================================================================
# Key Rotation Tests
# =============================================================================

class TestKeyRotation:
    """Tests for key selection and rotation."""

    def test_get_key_returns_healthy_key(self, manager):
        """Should return a non-DEAD key."""
        key = manager.get_key()
        assert key in ['key1', 'key2', 'key3']

    def test_skip_dead_keys(self, manager):
        """Should not return DEAD keys."""
        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        ))

        # Get key multiple times
        for _ in range(10):
            key = manager.get_key()
            assert key in ['key2', 'key3']
            assert key != 'key1'

    def test_return_none_when_all_dead(self, manager):
        """Should return None when all keys are DEAD."""
        auth_error = ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        )

        for key in ['key1', 'key2', 'key3']:
            manager.mark_failed(key, auth_error)

        assert manager.get_key() is None

    def test_get_key_count(self, manager):
        """get_key_count should return healthy key count."""
        assert manager.get_key_count() == 3

        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        ))

        assert manager.get_key_count() == 2


# =============================================================================
# Persistence Tests
# =============================================================================

class TestPersistence:
    """Tests for state persistence."""

    def test_state_persisted_to_file(self, temp_state_dir):
        """State should be saved to JSON file."""
        manager = ApiKeyManager(['key1'], state_dir=temp_state_dir)
        manager.mark_success('key1')

        state_file = Path(temp_state_dir) / 'api_key_state.json'
        assert state_file.exists()

        with open(state_file) as f:
            data = json.load(f)

        assert 'key1' in data
        assert data['key1']['success_count'] == 1

    def test_state_loaded_from_file(self, temp_state_dir):
        """State should be loaded on initialization."""
        state_file = Path(temp_state_dir) / 'api_key_state.json'
        state_file.write_text(json.dumps({
            'key1': {
                'fail_count': 3,
                'circuit_state': 'OPEN',
                'success_count': 10,
                'total_requests': 13,
            }
        }))

        manager = ApiKeyManager(['key1'], state_dir=temp_state_dir)

        states = manager.get_all_key_states()
        assert states[0]['fail_count'] == 3
        assert states[0]['circuit_state'] == 'OPEN'

    def test_dead_state_persists_across_instances(self, temp_state_dir):
        """DEAD state should persist across manager instances."""
        manager1 = ApiKeyManager(['key1', 'key2'], state_dir=temp_state_dir)
        manager1.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        ))

        manager2 = ApiKeyManager(['key1', 'key2'], state_dir=temp_state_dir)

        states = {s['key']: s for s in manager2.get_all_key_states()}
        assert states['...key1']['circuit_state'] == 'DEAD'


# =============================================================================
# Health Statistics Tests
# =============================================================================

class TestHealthStats:
    """Tests for get_stats() method."""

    def test_initial_stats(self, manager):
        """All keys should be healthy initially."""
        stats = manager.get_stats()
        assert stats['total'] == 3
        assert stats['healthy'] == 3
        assert stats['cooling'] == 0
        assert stats['dead'] == 0

    def test_stats_with_dead_key(self, manager):
        """Dead key should be counted."""
        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        ))

        stats = manager.get_stats()
        assert stats['dead'] == 1
        assert stats['healthy'] == 2


# =============================================================================
# Backoff Calculation Tests
# =============================================================================

class TestBackoffCalculation:
    """Tests for calculate_backoff() method."""

    def test_exponential_backoff(self, manager):
        """Backoff should increase exponentially."""
        delay0 = manager.calculate_backoff(0)
        delay1 = manager.calculate_backoff(1)
        delay2 = manager.calculate_backoff(2)

        # Allow for jitter (0-1000ms = 0-1s)
        assert 1.0 <= delay0 < 2.0
        assert 2.0 <= delay1 < 3.0
        assert 4.0 <= delay2 < 5.0

    def test_backoff_capped_at_max(self, manager):
        """Backoff should be capped at max."""
        delay = manager.calculate_backoff(10)
        assert delay <= 65  # 64s max + 1s jitter


# =============================================================================
# Key Management Tests
# =============================================================================

class TestKeyManagement:
    """Tests for key management methods."""

    def test_add_key(self, manager):
        """Should add new key to pool."""
        initial = manager.get_key_count()
        manager.add_key('key4')
        assert manager.get_key_count() == initial + 1

    def test_add_duplicate_key(self, manager):
        """Should not add duplicate key."""
        initial = manager.get_key_count()
        manager.add_key('key1')
        assert manager.get_key_count() == initial

    def test_remove_key(self, manager):
        """Should remove key from pool."""
        result = manager.remove_key('key1')
        assert result is True
        assert manager.get_key_count() == 2

    def test_revive_dead_key(self, manager):
        """Should revive a DEAD key."""
        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        ))

        result = manager.revive_key('key1')

        assert result is True
        states = {s['key']: s for s in manager.get_all_key_states()}
        assert states['...key1']['circuit_state'] == 'CLOSED'

    def test_reset_all(self, manager):
        """Should reset all keys to healthy state."""
        # Damage some keys
        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.QUOTA,
            retryable=True,
            cooldown_ms=60000,
            mark_key_failed=True,
            mark_key_dead=False
        ))

        manager.reset_all()

        stats = manager.get_stats()
        assert stats['healthy'] == 3
        assert stats['cooling'] == 0


# =============================================================================
# Singleton Tests
# =============================================================================

class TestSingleton:
    """Tests for singleton factory."""

    def test_singleton_created(self, temp_state_dir):
        """Should create singleton on first call."""
        reset_api_key_manager()

        # Create manager directly and verify it works
        manager = get_api_key_manager(['key1', 'key2'])
        assert manager is not None
        assert manager.get_key_count() == 2

        # Second call should return same instance
        manager2 = get_api_key_manager()
        assert manager is manager2

        # Cleanup
        reset_api_key_manager()

    def test_singleton_throws_if_not_initialized(self):
        """Should throw if not initialized."""
        reset_api_key_manager()

        with pytest.raises(ValueError, match="not initialized"):
            get_api_key_manager()


# =============================================================================
# Event Callback Tests
# =============================================================================

class TestEventCallbacks:
    """Tests for event callbacks."""

    def test_on_key_death_called(self, manager):
        """Callback should be called when key dies."""
        callback = Mock()
        manager.set_on_key_death(callback)

        manager.mark_failed('key1', ErrorClassification(
            error_type=ErrorType.AUTH,
            retryable=False,
            cooldown_ms=float('inf'),
            mark_key_failed=True,
            mark_key_dead=True
        ))

        callback.assert_called_once_with('key1')

    def test_on_all_exhausted_called(self, manager):
        """Callback should be called when all keys exhausted."""
        callback = Mock()
        manager.set_on_all_exhausted(callback)

        # Kill all keys
        for key in ['key1', 'key2', 'key3']:
            manager.mark_failed(key, ErrorClassification(
                error_type=ErrorType.AUTH,
                retryable=False,
                cooldown_ms=float('inf'),
                mark_key_failed=True,
                mark_key_dead=True
            ))

        # Try to get a key
        manager.get_key()

        callback.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
