#!/usr/bin/env python3
"""
Network Client with Connection Pooling, Retry Logic, and Circuit Breaker
Provides robust HTTP client with performance optimizations and fault tolerance.
"""

import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, Callable
from enum import Enum
from contextlib import contextmanager
import threading
from error_handler import (
    ErrorHandler, 
    NetworkError, 
    ErrorSeverity, 
    ErrorCategory,
    get_error_handler
)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for external services.
    Prevents cascading failures by stopping requests to failing services.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = Exception
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Time in seconds before attempting recovery
            expected_exception: Exception type to catch
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = CircuitState.CLOSED
        self._lock = threading.Lock()
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            NetworkError: If circuit is open
        """
        with self._lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                else:
                    raise NetworkError(
                        f"Circuit breaker is OPEN. Service unavailable. "
                        f"Will retry after {self.recovery_timeout}s",
                        severity=ErrorSeverity.HIGH
                    )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure()
            # Re-raise the original NetworkError if it already is one
            if isinstance(e, NetworkError):
                raise
            raise NetworkError(
                f"Request failed: {str(e)}",
                severity=ErrorSeverity.MEDIUM,
                original_exception=e
            )
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt recovery."""
        return (
            self.last_failure_time is not None and
            time.time() - self.last_failure_time >= self.recovery_timeout
        )
    
    def _on_success(self) -> None:
        """Handle successful request."""
        with self._lock:
            self.failure_count = 0
            self.state = CircuitState.CLOSED
    
    def _on_failure(self) -> None:
        """Handle failed request."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
    
    def reset(self) -> None:
        """Manually reset circuit breaker."""
        with self._lock:
            self.failure_count = 0
            self.last_failure_time = None
            self.state = CircuitState.CLOSED


class NetworkClient:
    """
    HTTP client with connection pooling, retry logic, and circuit breaker.
    Optimized for performance and fault tolerance.
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 0.3,
        timeout: tuple = (10, 30),  # (connect, read) timeout
        pool_connections: int = 10,
        pool_maxsize: int = 20,
        enable_circuit_breaker: bool = True,
        circuit_failure_threshold: int = 5,
        circuit_recovery_timeout: float = 60.0
    ):
        """
        Initialize network client with optimized settings.
        
        Args:
            max_retries: Maximum number of retry attempts
            backoff_factor: Backoff factor for retries (delay = backoff_factor * (2 ^ retry_count))
            timeout: Tuple of (connect_timeout, read_timeout) in seconds
            pool_connections: Number of connection pools to cache
            pool_maxsize: Maximum number of connections in each pool
            enable_circuit_breaker: Whether to use circuit breaker
            circuit_failure_threshold: Failures before circuit opens
            circuit_recovery_timeout: Time before attempting recovery
        """
        self.timeout = timeout
        self.error_handler = get_error_handler()
        
        # Create session with connection pooling
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP codes
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
            raise_on_status=False
        )
        
        # Configure HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        
        # Mount adapter for both HTTP and HTTPS
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Circuit breaker for fault tolerance
        self.circuit_breaker = None
        if enable_circuit_breaker:
            self.circuit_breaker = CircuitBreaker(
                failure_threshold=circuit_failure_threshold,
                recovery_timeout=circuit_recovery_timeout,
                expected_exception=requests.RequestException
            )
        
        # Rate limiting state
        self._rate_limit_lock = threading.Lock()
        self._last_request_time: Optional[float] = None
        self._min_request_interval: float = 0.0  # Can be configured per domain
    
    def _enforce_rate_limit(self, min_interval: float = 0.0) -> None:
        """
        Enforce rate limiting between requests.
        
        Args:
            min_interval: Minimum seconds between requests
        """
        if min_interval <= 0:
            return
        
        with self._rate_limit_lock:
            if self._last_request_time:
                elapsed = time.time() - self._last_request_time
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
            self._last_request_time = time.time()
    
    def _make_request(
        self,
        method: str,
        url: str,
        timeout: Optional[tuple] = None,
        **kwargs
    ) -> requests.Response:
        """
        Internal method to make HTTP request.
        
        Args:
            method: HTTP method
            url: Request URL
            timeout: Optional custom timeout
            **kwargs: Additional request arguments
            
        Returns:
            Response object
        """
        timeout = timeout or self.timeout
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=timeout,
                **kwargs
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            return response
            
        except requests.Timeout as e:
            raise NetworkError(
                f"Request timeout for {url}",
                severity=ErrorSeverity.MEDIUM,
                original_exception=e,
                context={'url': url, 'timeout': timeout}
            )
        except requests.ConnectionError as e:
            raise NetworkError(
                f"Connection error for {url}",
                severity=ErrorSeverity.HIGH,
                original_exception=e,
                context={'url': url}
            )
        except requests.HTTPError as e:
            status_code = getattr(e.response, 'status_code', 'unknown') if hasattr(e, 'response') else 'unknown'
            raise NetworkError(
                f"HTTP error for {url}: {status_code}",
                severity=ErrorSeverity.MEDIUM,
                original_exception=e,
                context={'url': url, 'status_code': status_code}
            )
        except requests.RequestException as e:
            raise NetworkError(
                f"Request failed for {url}",
                severity=ErrorSeverity.MEDIUM,
                original_exception=e,
                context={'url': url}
            )
    
    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[tuple] = None,
        rate_limit: float = 0.0,
        **kwargs
    ) -> requests.Response:
        """
        Make GET request with retry and circuit breaker.
        
        Args:
            url: Request URL
            params: Query parameters
            headers: Request headers
            timeout: Custom timeout (connect, read)
            rate_limit: Minimum seconds between requests
            **kwargs: Additional request arguments
            
        Returns:
            Response object
        """
        self._enforce_rate_limit(rate_limit)
        
        request_func = lambda: self._make_request(
            'GET', url, timeout=timeout, params=params, headers=headers, **kwargs
        )
        
        if self.circuit_breaker:
            return self.circuit_breaker.call(request_func)
        return request_func()
    
    def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[tuple] = None,
        rate_limit: float = 0.0,
        **kwargs
    ) -> requests.Response:
        """
        Make POST request with retry and circuit breaker.
        
        Args:
            url: Request URL
            data: Request body data
            json: JSON request body
            headers: Request headers
            timeout: Custom timeout (connect, read)
            rate_limit: Minimum seconds between requests
            **kwargs: Additional request arguments
            
        Returns:
            Response object
        """
        self._enforce_rate_limit(rate_limit)
        
        request_func = lambda: self._make_request(
            'POST', url, timeout=timeout, data=data, json=json, headers=headers, **kwargs
        )
        
        if self.circuit_breaker:
            return self.circuit_breaker.call(request_func)
        return request_func()
    
    def put(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[tuple] = None,
        rate_limit: float = 0.0,
        **kwargs
    ) -> requests.Response:
        """Make PUT request with retry and circuit breaker."""
        self._enforce_rate_limit(rate_limit)
        
        request_func = lambda: self._make_request(
            'PUT', url, timeout=timeout, data=data, json=json, headers=headers, **kwargs
        )
        
        if self.circuit_breaker:
            return self.circuit_breaker.call(request_func)
        return request_func()
    
    def delete(
        self,
        url: str,
        headers: Optional[Dict] = None,
        timeout: Optional[tuple] = None,
        rate_limit: float = 0.0,
        **kwargs
    ) -> requests.Response:
        """Make DELETE request with retry and circuit breaker."""
        self._enforce_rate_limit(rate_limit)
        
        request_func = lambda: self._make_request(
            'DELETE', url, timeout=timeout, headers=headers, **kwargs
        )
        
        if self.circuit_breaker:
            return self.circuit_breaker.call(request_func)
        return request_func()
    
    def close(self) -> None:
        """Close the session and release resources."""
        self.session.close()
    
    @contextmanager
    def managed_session(self):
        """Context manager for automatic session cleanup."""
        try:
            yield self
        finally:
            self.close()
    
    def reset_circuit_breaker(self) -> None:
        """Manually reset circuit breaker."""
        if self.circuit_breaker:
            self.circuit_breaker.reset()
    
    def get_circuit_state(self) -> Optional[CircuitState]:
        """Get current circuit breaker state."""
        return self.circuit_breaker.state if self.circuit_breaker else None


# Global network client instance
_global_network_client: Optional[NetworkClient] = None


def get_network_client() -> NetworkClient:
    """
    Get or create the global network client instance.
    
    Returns:
        Configured NetworkClient instance
    """
    global _global_network_client
    
    if _global_network_client is None:
        _global_network_client = NetworkClient()
    
    return _global_network_client


def close_network_client() -> None:
    """Close and reset the global network client."""
    global _global_network_client
    
    if _global_network_client:
        _global_network_client.close()
        _global_network_client = None
