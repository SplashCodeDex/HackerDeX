#!/usr/bin/env python3
"""
Centralized Error Handling Framework for HackingTool
Provides robust error handling with logging, retry mechanisms, and error recovery.
"""

import logging
import traceback
import time
from typing import Callable, Any, Optional, Type, Tuple, Dict
from functools import wraps
from enum import Enum
import sys


class ErrorSeverity(Enum):
    """Error severity levels for categorization and handling"""
    LOW = "low"           # Minor issues, can continue operation
    MEDIUM = "medium"     # Important but not critical
    HIGH = "high"         # Critical but recoverable
    CRITICAL = "critical" # System-breaking, requires immediate attention


class ErrorCategory(Enum):
    """Categories of errors for better tracking and handling"""
    NETWORK = "network"
    FILE_IO = "file_io"
    SUBPROCESS = "subprocess"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    PERMISSION = "permission"
    CONFIGURATION = "configuration"
    EXTERNAL_API = "external_api"
    DATABASE = "database"
    PARSING = "parsing"
    UNKNOWN = "unknown"


class HackingToolError(Exception):
    """Base exception for all HackingTool errors"""
    def __init__(
        self, 
        message: str, 
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        original_exception: Optional[Exception] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.category = category
        self.original_exception = original_exception
        self.context = context or {}
        self.timestamp = time.time()


class NetworkError(HackingToolError):
    """Network-related errors"""
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.NETWORK)
        super().__init__(message, **kwargs)


class SubprocessError(HackingToolError):
    """Subprocess execution errors"""
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.SUBPROCESS)
        super().__init__(message, **kwargs)


class ValidationError(HackingToolError):
    """Input validation errors"""
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.VALIDATION)
        kwargs.setdefault('severity', ErrorSeverity.LOW)
        super().__init__(message, **kwargs)


class ErrorHandler:
    """
    Centralized error handler with logging, retry mechanisms, and error recovery.
    """
    
    def __init__(self, logger_name: str = "hackingtool"):
        """
        Initialize error handler with logging configuration.
        
        Args:
            logger_name: Name for the logger instance
        """
        self.logger = self._setup_logger(logger_name)
        self.error_counts: Dict[str, int] = {}
        self.last_errors: Dict[str, float] = {}
    
    @staticmethod
    def _setup_logger(name: str) -> logging.Logger:
        """
        Set up logger with file and console handlers.
        
        Args:
            name: Logger name
            
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)
        
        # Avoid duplicate handlers
        if logger.handlers:
            return logger
        
        logger.setLevel(logging.DEBUG)
        
        # Console handler - INFO and above
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(levelname)s - %(name)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        # File handler - DEBUG and above
        try:
            file_handler = logging.FileHandler('hackingtool_errors.log')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(name)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except (IOError, PermissionError) as e:
            # If we can't create log file, continue with console only
            print(f"Warning: Could not create log file: {e}", file=sys.stderr)
        
        logger.addHandler(console_handler)
        return logger
    
    def log_error(
        self, 
        error: Exception, 
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        context: Optional[Dict[str, Any]] = None,
        include_traceback: bool = True
    ) -> None:
        """
        Log an error with appropriate severity and context.
        
        Args:
            error: The exception to log
            severity: Error severity level
            category: Error category
            context: Additional context information
            include_traceback: Whether to include full traceback
        """
        context = context or {}
        error_key = f"{category.value}:{type(error).__name__}"
        
        # Track error frequency
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        self.last_errors[error_key] = time.time()
        
        # Build error message
        message = f"[{category.value.upper()}] {type(error).__name__}: {str(error)}"
        
        if context:
            message += f" | Context: {context}"
        
        message += f" | Count: {self.error_counts[error_key]}"
        
        # Log based on severity
        if severity == ErrorSeverity.CRITICAL:
            self.logger.critical(message)
            if include_traceback:
                self.logger.critical(traceback.format_exc())
        elif severity == ErrorSeverity.HIGH:
            self.logger.error(message)
            if include_traceback:
                self.logger.error(traceback.format_exc())
        elif severity == ErrorSeverity.MEDIUM:
            self.logger.warning(message)
            if include_traceback:
                self.logger.debug(traceback.format_exc())
        else:  # LOW
            self.logger.info(message)
            if include_traceback:
                self.logger.debug(traceback.format_exc())
    
    def handle_error(
        self,
        error: Exception,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        context: Optional[Dict[str, Any]] = None,
        reraise: bool = False,
        default_return: Any = None
    ) -> Any:
        """
        Handle an error with logging and optional re-raising.
        
        Args:
            error: The exception to handle
            severity: Error severity level
            category: Error category
            context: Additional context information
            reraise: Whether to re-raise the exception
            default_return: Default value to return if not re-raising
            
        Returns:
            default_return value if not re-raising, otherwise raises
        """
        self.log_error(error, severity, category, context)
        
        if reraise:
            raise error
        
        return default_return
    
    def with_retry(
        self,
        func: Callable,
        max_attempts: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: Tuple[Type[Exception], ...] = (Exception,),
        on_retry: Optional[Callable[[Exception, int], None]] = None
    ) -> Callable:
        """
        Decorator to retry a function on failure with exponential backoff.
        
        Args:
            func: Function to retry
            max_attempts: Maximum number of retry attempts
            delay: Initial delay between retries in seconds
            backoff: Backoff multiplier for delay
            exceptions: Tuple of exceptions to catch and retry
            on_retry: Optional callback function called on each retry
            
        Returns:
            Wrapped function with retry logic
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_attempts - 1:
                        self.logger.warning(
                            f"Attempt {attempt + 1}/{max_attempts} failed for {func.__name__}: {e}. "
                            f"Retrying in {current_delay}s..."
                        )
                        
                        if on_retry:
                            on_retry(e, attempt + 1)
                        
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        self.log_error(
                            e,
                            severity=ErrorSeverity.HIGH,
                            context={
                                'function': func.__name__,
                                'attempts': max_attempts,
                                'args': str(args)[:100],
                                'kwargs': str(kwargs)[:100]
                            }
                        )
            
            raise last_exception
        
        return wrapper
    
    def safe_execute(
        self,
        func: Callable,
        *args,
        default_return: Any = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        context: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Any:
        """
        Safely execute a function with error handling.
        
        Args:
            func: Function to execute
            *args: Positional arguments for func
            default_return: Value to return on error
            severity: Error severity level
            category: Error category
            context: Additional context information
            **kwargs: Keyword arguments for func
            
        Returns:
            Function result or default_return on error
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return self.handle_error(
                e,
                severity=severity,
                category=category,
                context=context or {'function': func.__name__},
                default_return=default_return
            )
    
    def get_error_stats(self) -> Dict[str, Any]:
        """
        Get statistics about logged errors.
        
        Returns:
            Dictionary containing error statistics
        """
        return {
            'total_errors': sum(self.error_counts.values()),
            'error_types': len(self.error_counts),
            'error_counts': dict(self.error_counts),
            'last_errors': dict(self.last_errors)
        }
    
    def reset_stats(self) -> None:
        """Reset error statistics."""
        self.error_counts.clear()
        self.last_errors.clear()


# Global error handler instance
_global_error_handler = ErrorHandler()


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance."""
    return _global_error_handler


# Convenience decorators
def with_error_handling(
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    default_return: Any = None,
    reraise: bool = False
):
    """
    Decorator for automatic error handling on functions.
    
    Args:
        severity: Error severity level
        category: Error category
        default_return: Default value to return on error
        reraise: Whether to re-raise exceptions
        
    Example:
        @with_error_handling(category=ErrorCategory.NETWORK, default_return=[])
        def fetch_data():
            return requests.get('https://api.example.com').json()
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                return _global_error_handler.handle_error(
                    e,
                    severity=severity,
                    category=category,
                    context={'function': func.__name__},
                    reraise=reraise,
                    default_return=default_return
                )
        return wrapper
    return decorator


def retry_on_failure(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Decorator for automatic retry on function failure.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Backoff multiplier for delay
        exceptions: Tuple of exceptions to catch and retry
        
    Example:
        @retry_on_failure(max_attempts=3, delay=2.0)
        def unstable_operation():
            # May fail occasionally
            pass
    """
    def decorator(func: Callable) -> Callable:
        return _global_error_handler.with_retry(
            func,
            max_attempts=max_attempts,
            delay=delay,
            backoff=backoff,
            exceptions=exceptions
        )
    return decorator
