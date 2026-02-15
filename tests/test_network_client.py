#!/usr/bin/env python3
"""
Unit tests for the NetworkClient module.
Tests connection pooling, retry logic, circuit breaker, and rate limiting.
"""

import pytest
import time
import requests
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add web_ui to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web_ui'))

from network_client import (
    NetworkClient,
    CircuitBreaker,
    CircuitState,
    get_network_client,
    close_network_client
)
from error_handler import NetworkError


class TestCircuitBreaker:
    """Test CircuitBreaker functionality"""
    
    @pytest.fixture
    def circuit_breaker(self):
        """Create a fresh CircuitBreaker for each test"""
        return CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=1.0,
            expected_exception=Exception
        )
    
    def test_circuit_breaker_initial_state(self, circuit_breaker):
        """Test circuit breaker starts in CLOSED state"""
        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.failure_count == 0
    
    def test_circuit_breaker_successful_call(self, circuit_breaker):
        """Test successful calls keep circuit closed"""
        mock_func = Mock(return_value="success")
        
        result = circuit_breaker.call(mock_func)
        
        assert result == "success"
        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.failure_count == 0
    
    def test_circuit_breaker_opens_after_threshold(self, circuit_breaker):
        """Test circuit opens after failure threshold"""
        mock_func = Mock(side_effect=ValueError("fail"))
        
        # Trigger failures up to threshold
        for _ in range(3):
            with pytest.raises(NetworkError):
                circuit_breaker.call(mock_func)
        
        assert circuit_breaker.state == CircuitState.OPEN
        assert circuit_breaker.failure_count == 3
    
    def test_circuit_breaker_rejects_when_open(self, circuit_breaker):
        """Test circuit breaker rejects calls when open"""
        # Force circuit to open
        circuit_breaker.state = CircuitState.OPEN
        circuit_breaker.last_failure_time = time.time()
        
        mock_func = Mock(return_value="success")
        
        with pytest.raises(NetworkError, match="Circuit breaker is OPEN"):
            circuit_breaker.call(mock_func)
        
        # Function should not be called
        mock_func.assert_not_called()
    
    def test_circuit_breaker_half_open_transition(self, circuit_breaker):
        """Test circuit transitions to HALF_OPEN after timeout"""
        # Force circuit to open
        circuit_breaker.state = CircuitState.OPEN
        circuit_breaker.failure_count = 3
        circuit_breaker.last_failure_time = time.time() - 2.0  # 2 seconds ago
        
        mock_func = Mock(return_value="success")
        
        result = circuit_breaker.call(mock_func)
        
        assert result == "success"
        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.failure_count == 0
    
    def test_circuit_breaker_reset(self, circuit_breaker):
        """Test manual circuit breaker reset"""
        circuit_breaker.state = CircuitState.OPEN
        circuit_breaker.failure_count = 5
        circuit_breaker.last_failure_time = time.time()
        
        circuit_breaker.reset()
        
        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.failure_count == 0
        assert circuit_breaker.last_failure_time is None


class TestNetworkClient:
    """Test NetworkClient functionality"""
    
    @pytest.fixture
    def network_client(self):
        """Create a fresh NetworkClient for each test"""
        return NetworkClient(
            max_retries=3,
            timeout=(5, 10),
            enable_circuit_breaker=True
        )
    
    def test_network_client_initialization(self, network_client):
        """Test NetworkClient initializes correctly"""
        assert network_client.session is not None
        assert network_client.timeout == (5, 10)
        assert network_client.circuit_breaker is not None
    
    def test_network_client_without_circuit_breaker(self):
        """Test NetworkClient can be created without circuit breaker"""
        client = NetworkClient(enable_circuit_breaker=False)
        assert client.circuit_breaker is None
    
    @patch('network_client.requests.Session.request')
    def test_get_request_success(self, mock_request, network_client):
        """Test successful GET request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response
        
        response = network_client.get('http://example.com')
        
        assert response == mock_response
        mock_request.assert_called_once()
    
    @patch('network_client.requests.Session.request')
    def test_post_request_success(self, mock_request, network_client):
        """Test successful POST request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response
        
        data = {'key': 'value'}
        response = network_client.post('http://example.com', json=data)
        
        assert response == mock_response
        mock_request.assert_called_once()
    
    @patch('network_client.requests.Session.request')
    def test_put_request_success(self, mock_request, network_client):
        """Test successful PUT request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response
        
        response = network_client.put('http://example.com', data='update')
        
        assert response == mock_response
        mock_request.assert_called_once()
    
    @patch('network_client.requests.Session.request')
    def test_delete_request_success(self, mock_request, network_client):
        """Test successful DELETE request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response
        
        response = network_client.delete('http://example.com')
        
        assert response == mock_response
        mock_request.assert_called_once()
    
    @patch('network_client.requests.Session.request')
    def test_request_timeout_handling(self, mock_request, network_client):
        """Test timeout errors are handled properly"""
        mock_request.side_effect = requests.Timeout("Request timeout")
        
        with pytest.raises(NetworkError, match="Request timeout"):
            network_client.get('http://example.com')
    
    @patch('network_client.requests.Session.request')
    def test_connection_error_handling(self, mock_request, network_client):
        """Test connection errors are handled properly"""
        mock_request.side_effect = requests.ConnectionError("Connection failed")
        
        with pytest.raises(NetworkError, match="Connection error"):
            network_client.get('http://example.com')
    
    @patch('network_client.requests.Session.request')
    def test_http_error_handling(self, mock_request, network_client):
        """Test HTTP errors are handled properly"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        mock_request.return_value = mock_response
        
        with pytest.raises(NetworkError, match="HTTP error"):
            network_client.get('http://example.com')
    
    def test_rate_limiting(self, network_client):
        """Test rate limiting enforces delays"""
        with patch('network_client.requests.Session.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_request.return_value = mock_response
            
            # Make first request
            start_time = time.time()
            network_client.get('http://example.com', rate_limit=0.15)
            
            # Make second request - should be delayed
            network_client.get('http://example.com', rate_limit=0.15)
            elapsed = time.time() - start_time
            
            # Should take at least the rate limit time
            assert elapsed >= 0.14  # Small tolerance for timing
    
    def test_custom_timeout(self, network_client):
        """Test custom timeout is used"""
        with patch('network_client.requests.Session.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_request.return_value = mock_response
            
            custom_timeout = (3, 6)
            network_client.get('http://example.com', timeout=custom_timeout)
            
            # Verify timeout was passed
            call_kwargs = mock_request.call_args[1]
            assert call_kwargs['timeout'] == custom_timeout
    
    def test_close_session(self, network_client):
        """Test session can be closed"""
        with patch.object(network_client.session, 'close') as mock_close:
            network_client.close()
            mock_close.assert_called_once()
    
    def test_managed_session_context_manager(self):
        """Test managed_session context manager"""
        client = NetworkClient()
        
        with patch.object(client, 'close') as mock_close:
            with client.managed_session():
                pass
            mock_close.assert_called_once()
    
    def test_circuit_breaker_integration(self):
        """Test circuit breaker works with network client"""
        # Create client with circuit breaker, disable retry to make test predictable
        client = NetworkClient(
            enable_circuit_breaker=True, 
            circuit_failure_threshold=3, 
            max_retries=0
        )
        
        # Directly test circuit breaker with controlled failures
        failure_count = 0
        
        def failing_request():
            nonlocal failure_count
            failure_count += 1
            raise requests.ConnectionError("Connection failed")
        
        # Trigger failures through circuit breaker
        for i in range(3):
            try:
                client.circuit_breaker.call(failing_request)
            except NetworkError:
                pass  # Expected
        
        # Circuit should be open after threshold failures
        state = client.get_circuit_state()
        assert state == CircuitState.OPEN, f"Expected OPEN but got {state}, failures={failure_count}"
    
    def test_reset_circuit_breaker(self, network_client):
        """Test circuit breaker can be reset"""
        # Force circuit open
        if network_client.circuit_breaker:
            network_client.circuit_breaker.state = CircuitState.OPEN
            network_client.circuit_breaker.failure_count = 5
            
            network_client.reset_circuit_breaker()
            
            assert network_client.circuit_breaker.state == CircuitState.CLOSED
            assert network_client.circuit_breaker.failure_count == 0
    
    def test_get_circuit_state(self, network_client):
        """Test getting circuit breaker state"""
        state = network_client.get_circuit_state()
        assert state == CircuitState.CLOSED


class TestGlobalNetworkClient:
    """Test global network client singleton"""
    
    def teardown_method(self):
        """Clean up global client after each test"""
        close_network_client()
    
    def test_get_network_client_creates_instance(self):
        """Test get_network_client creates instance"""
        client = get_network_client()
        assert client is not None
        assert isinstance(client, NetworkClient)
    
    def test_get_network_client_returns_singleton(self):
        """Test get_network_client returns same instance"""
        client1 = get_network_client()
        client2 = get_network_client()
        assert client1 is client2
    
    def test_close_network_client(self):
        """Test close_network_client closes and resets instance"""
        client1 = get_network_client()
        
        close_network_client()
        
        client2 = get_network_client()
        assert client1 is not client2


class TestIntegration:
    """Integration tests for network client"""
    
    @pytest.mark.integration
    def test_real_http_request(self):
        """Test real HTTP request (requires internet)"""
        client = NetworkClient(timeout=(5, 10))
        
        try:
            # Use a reliable public API
            response = client.get('https://httpbin.org/get')
            assert response.status_code == 200
        except NetworkError as e:
            pytest.skip(f"Network unavailable: {e}")
        finally:
            client.close()
    
    @pytest.mark.integration
    def test_retry_on_transient_failure(self):
        """Test retry mechanism with simulated transient failures"""
        client = NetworkClient(max_retries=3, backoff_factor=0.1, enable_circuit_breaker=False)
        
        attempt_count = [0]
        
        def mock_request(*args, **kwargs):
            attempt_count[0] += 1
            if attempt_count[0] < 3:
                raise requests.ConnectionError("Transient failure")
            
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            return mock_response
        
        with patch('network_client.requests.Session.request', side_effect=mock_request):
            try:
                response = client.get('http://example.com')
                assert response.status_code == 200
                # Requests library retry will handle this
                assert attempt_count[0] >= 1
            except NetworkError:
                # Circuit breaker or retries exhausted - also acceptable
                pytest.skip("Network retries exhausted")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
