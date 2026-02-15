#!/usr/bin/env python3
"""
Unit tests for the ErrorHandler module.
Tests error logging, retry mechanisms, and error recovery.
"""

import pytest
import time
import logging
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add web_ui to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web_ui'))

from error_handler import (
    ErrorHandler,
    ErrorSeverity,
    ErrorCategory,
    HackingToolError,
    NetworkError,
    SubprocessError,
    ValidationError,
    get_error_handler,
    with_error_handling,
    retry_on_failure
)


class TestErrorClasses:
    """Test custom error classes"""
    
    def test_hacking_tool_error_creation(self):
        """Test HackingToolError creation with all parameters"""
        original_error = ValueError("Original error")
        context = {"key": "value", "number": 42}
        
        error = HackingToolError(
            message="Test error",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.NETWORK,
            original_exception=original_error,
            context=context
        )
        
        assert error.message == "Test error"
        assert error.severity == ErrorSeverity.HIGH
        assert error.category == ErrorCategory.NETWORK
        assert error.original_exception == original_error
        assert error.context == context
        assert isinstance(error.timestamp, float)
    
    def test_network_error_defaults(self):
        """Test NetworkError has correct default category"""
        error = NetworkError("Network failed")
        assert error.category == ErrorCategory.NETWORK
    
    def test_subprocess_error_defaults(self):
        """Test SubprocessError has correct default category"""
        error = SubprocessError("Process failed")
        assert error.category == ErrorCategory.SUBPROCESS
    
    def test_validation_error_defaults(self):
        """Test ValidationError has correct defaults"""
        error = ValidationError("Invalid input")
        assert error.category == ErrorCategory.VALIDATION
        assert error.severity == ErrorSeverity.LOW


class TestErrorHandler:
    """Test ErrorHandler functionality"""
    
    @pytest.fixture
    def error_handler(self):
        """Create a fresh ErrorHandler instance for each test"""
        return ErrorHandler(logger_name="test_logger")
    
    def test_error_handler_initialization(self, error_handler):
        """Test ErrorHandler initializes correctly"""
        assert error_handler.logger is not None
        assert isinstance(error_handler.error_counts, dict)
        assert isinstance(error_handler.last_errors, dict)
    
    def test_log_error_tracks_frequency(self, error_handler):
        """Test that errors are tracked by frequency"""
        error = ValueError("Test error")
        
        # Log same error multiple times
        for _ in range(3):
            error_handler.log_error(
                error,
                severity=ErrorSeverity.MEDIUM,
                category=ErrorCategory.VALIDATION
            )
        
        error_key = f"{ErrorCategory.VALIDATION.value}:{type(error).__name__}"
        assert error_handler.error_counts[error_key] == 3
        assert error_key in error_handler.last_errors
    
    def test_log_error_different_severities(self, error_handler, caplog):
        """Test logging with different severity levels"""
        error = RuntimeError("Test error")
        
        with caplog.at_level(logging.DEBUG):
            # CRITICAL severity
            error_handler.log_error(error, severity=ErrorSeverity.CRITICAL)
            assert any("CRITICAL" in record.levelname for record in caplog.records)
            
            caplog.clear()
            
            # HIGH severity
            error_handler.log_error(error, severity=ErrorSeverity.HIGH)
            assert any("ERROR" in record.levelname for record in caplog.records)
    
    def test_handle_error_with_reraise(self, error_handler):
        """Test error handling with reraise option"""
        error = ValueError("Test error")
        
        with pytest.raises(ValueError):
            error_handler.handle_error(
                error,
                severity=ErrorSeverity.MEDIUM,
                category=ErrorCategory.VALIDATION,
                reraise=True
            )
    
    def test_handle_error_with_default_return(self, error_handler):
        """Test error handling returns default value"""
        error = ValueError("Test error")
        
        result = error_handler.handle_error(
            error,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.VALIDATION,
            reraise=False,
            default_return="default_value"
        )
        
        assert result == "default_value"
    
    def test_safe_execute_success(self, error_handler):
        """Test safe_execute with successful function"""
        def successful_func(x, y):
            return x + y
        
        result = error_handler.safe_execute(successful_func, 2, 3)
        assert result == 5
    
    def test_safe_execute_with_error(self, error_handler):
        """Test safe_execute handles errors gracefully"""
        def failing_func():
            raise ValueError("Function failed")
        
        result = error_handler.safe_execute(
            failing_func,
            default_return="fallback",
            severity=ErrorSeverity.LOW
        )
        
        assert result == "fallback"
    
    def test_with_retry_success(self, error_handler):
        """Test retry mechanism with successful function"""
        mock_func = Mock(return_value="success")
        
        wrapped_func = error_handler.with_retry(mock_func, max_attempts=3)
        result = wrapped_func()
        
        assert result == "success"
        assert mock_func.call_count == 1
    
    def test_with_retry_eventual_success(self, error_handler):
        """Test retry mechanism succeeds after failures"""
        attempt = [0]
        
        def flaky_func():
            attempt[0] += 1
            if attempt[0] < 3:
                raise ValueError("fail")
            return "success"
        
        wrapped_func = error_handler.with_retry(
            flaky_func,
            max_attempts=3,
            delay=0.01,
            exceptions=(ValueError,)
        )
        
        result = wrapped_func()
        
        assert result == "success"
        assert attempt[0] == 3
    
    def test_with_retry_max_attempts_exceeded(self, error_handler):
        """Test retry mechanism fails after max attempts"""
        attempt = [0]
        
        def always_fails():
            attempt[0] += 1
            raise ValueError("persistent failure")
        
        wrapped_func = error_handler.with_retry(
            always_fails,
            max_attempts=3,
            delay=0.01,
            exceptions=(ValueError,)
        )
        
        with pytest.raises(ValueError, match="persistent failure"):
            wrapped_func()
        
        assert attempt[0] == 3
    
    def test_with_retry_exponential_backoff(self, error_handler):
        """Test retry uses exponential backoff"""
        call_times = []
        
        def failing_func():
            call_times.append(time.time())
            raise ValueError("fail")
        
        wrapped_func = error_handler.with_retry(
            failing_func,
            max_attempts=3,
            delay=0.1,
            backoff=2.0,
            exceptions=(ValueError,)
        )
        
        with pytest.raises(ValueError):
            wrapped_func()
        
        # Check that delays increase
        assert len(call_times) == 3
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]
        assert delay2 > delay1  # Second delay should be longer
    
    def test_with_retry_on_retry_callback(self, error_handler):
        """Test on_retry callback is called"""
        callback_calls = []
        attempt = [0]
        
        def on_retry_callback(error, attempt_num):
            callback_calls.append((str(error), attempt_num))
        
        def flaky_func():
            attempt[0] += 1
            if attempt[0] < 3:
                raise ValueError(f"fail{attempt[0]}")
            return "success"
        
        wrapped_func = error_handler.with_retry(
            flaky_func,
            max_attempts=3,
            delay=0.01,
            on_retry=on_retry_callback
        )
        
        wrapped_func()
        
        assert len(callback_calls) == 2
        assert callback_calls[0][1] == 1  # First retry
        assert callback_calls[1][1] == 2  # Second retry
    
    def test_get_error_stats(self, error_handler):
        """Test error statistics retrieval"""
        errors = [
            ValueError("error1"),
            ValueError("error2"),
            TypeError("error3")
        ]
        
        for error in errors:
            error_handler.log_error(error, category=ErrorCategory.VALIDATION)
        
        stats = error_handler.get_error_stats()
        
        assert stats['total_errors'] == 3
        assert stats['error_types'] > 0
        assert 'error_counts' in stats
        assert 'last_errors' in stats
    
    def test_reset_stats(self, error_handler):
        """Test error statistics reset"""
        error = ValueError("test error")
        error_handler.log_error(error)
        
        assert len(error_handler.error_counts) > 0
        
        error_handler.reset_stats()
        
        assert len(error_handler.error_counts) == 0
        assert len(error_handler.last_errors) == 0


class TestDecorators:
    """Test decorator functions"""
    
    def test_with_error_handling_decorator_success(self):
        """Test with_error_handling decorator on successful function"""
        @with_error_handling(category=ErrorCategory.NETWORK, default_return=None)
        def fetch_data():
            return {"data": "success"}
        
        result = fetch_data()
        assert result == {"data": "success"}
    
    def test_with_error_handling_decorator_failure(self):
        """Test with_error_handling decorator handles errors"""
        @with_error_handling(
            category=ErrorCategory.NETWORK,
            default_return={"error": "fallback"}
        )
        def fetch_data():
            raise ConnectionError("Network failed")
        
        result = fetch_data()
        assert result == {"error": "fallback"}
    
    def test_with_error_handling_decorator_reraise(self):
        """Test with_error_handling decorator with reraise"""
        @with_error_handling(
            category=ErrorCategory.NETWORK,
            reraise=True
        )
        def fetch_data():
            raise ConnectionError("Network failed")
        
        with pytest.raises(ConnectionError):
            fetch_data()
    
    def test_retry_on_failure_decorator_success(self):
        """Test retry_on_failure decorator on successful function"""
        mock_func = Mock(return_value="success")
        
        @retry_on_failure(max_attempts=3, delay=0.01)
        def operation():
            return mock_func()
        
        result = operation()
        assert result == "success"
        assert mock_func.call_count == 1
    
    def test_retry_on_failure_decorator_retries(self):
        """Test retry_on_failure decorator retries on failure"""
        attempt_count = [0]
        
        @retry_on_failure(max_attempts=3, delay=0.01)
        def unstable_operation():
            attempt_count[0] += 1
            if attempt_count[0] < 3:
                raise ValueError("Not yet")
            return "success"
        
        result = unstable_operation()
        assert result == "success"
        assert attempt_count[0] == 3
    
    def test_retry_on_failure_decorator_specific_exceptions(self):
        """Test retry_on_failure only catches specified exceptions"""
        @retry_on_failure(max_attempts=3, delay=0.01, exceptions=(ValueError,))
        def operation():
            raise TypeError("Wrong exception type")
        
        # Should not retry TypeError, only ValueError
        with pytest.raises(TypeError):
            operation()


class TestGlobalErrorHandler:
    """Test global error handler singleton"""
    
    def test_get_error_handler_returns_same_instance(self):
        """Test that get_error_handler returns singleton"""
        handler1 = get_error_handler()
        handler2 = get_error_handler()
        
        assert handler1 is handler2
    
    def test_global_error_handler_is_functional(self):
        """Test global error handler works correctly"""
        handler = get_error_handler()
        
        # Reset stats for clean test
        handler.reset_stats()
        
        error = ValueError("test error")
        handler.log_error(error)
        
        stats = handler.get_error_stats()
        assert stats['total_errors'] > 0


class TestIntegration:
    """Integration tests for error handling"""
    
    def test_error_handling_with_context(self):
        """Test error handling preserves context information"""
        handler = ErrorHandler(logger_name="integration_test")
        
        context = {
            'user': 'test_user',
            'operation': 'data_fetch',
            'timestamp': time.time()
        }
        
        error = NetworkError(
            "Connection failed",
            severity=ErrorSeverity.HIGH,
            context=context
        )
        
        assert error.context == context
        assert error.category == ErrorCategory.NETWORK
    
    def test_nested_error_handling(self):
        """Test error handling in nested function calls"""
        handler = ErrorHandler()
        
        def inner_func():
            raise ValueError("Inner error")
        
        def outer_func():
            return handler.safe_execute(
                inner_func,
                default_return="outer_fallback"
            )
        
        result = handler.safe_execute(
            outer_func,
            default_return="should_not_reach"
        )
        
        assert result == "outer_fallback"
    
    def test_error_handler_thread_safety(self):
        """Test error handler is thread-safe"""
        import threading
        
        handler = ErrorHandler()
        handler.reset_stats()
        errors_logged = []
        
        def log_errors():
            for i in range(10):
                try:
                    raise ValueError(f"Error {i}")
                except ValueError as e:
                    handler.log_error(e)
                    errors_logged.append(i)
        
        threads = [threading.Thread(target=log_errors) for _ in range(5)]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        stats = handler.get_error_stats()
        assert stats['total_errors'] == 50  # 5 threads * 10 errors each


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
