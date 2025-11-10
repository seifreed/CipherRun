"""CipherRun SDK exceptions.

This module defines all custom exceptions for the CipherRun Python SDK.
"""

from typing import Optional, Dict, Any


class CipherRunError(Exception):
    """Base exception for all CipherRun SDK errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.status_code:
            return f"[{self.status_code}] {self.message}"
        return self.message


class APIError(CipherRunError):
    """Generic API error."""
    pass


class BadRequestError(CipherRunError):
    """HTTP 400 Bad Request error."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=400, details=details)


class UnauthorizedError(CipherRunError):
    """HTTP 401 Unauthorized error."""

    def __init__(self, message: str = "API key is missing or invalid", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=401, details=details)


class ForbiddenError(CipherRunError):
    """HTTP 403 Forbidden error."""

    def __init__(self, message: str = "Access forbidden", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=403, details=details)


class NotFoundError(CipherRunError):
    """HTTP 404 Not Found error."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=404, details=details)


class ConflictError(CipherRunError):
    """HTTP 409 Conflict error."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=409, details=details)


class RateLimitError(CipherRunError):
    """HTTP 429 Rate Limit Exceeded error."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, status_code=429, details=details)
        self.retry_after = retry_after

    def __str__(self) -> str:
        if self.retry_after:
            return f"[429] {self.message} (retry after {self.retry_after}s)"
        return f"[429] {self.message}"


class InternalServerError(CipherRunError):
    """HTTP 500 Internal Server Error."""

    def __init__(self, message: str = "Internal server error", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=500, details=details)


class ServiceUnavailableError(CipherRunError):
    """HTTP 503 Service Unavailable error."""

    def __init__(self, message: str = "Service unavailable", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=503, details=details)


class TimeoutError(CipherRunError):
    """Request timeout error."""

    def __init__(self, message: str = "Request timed out", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=408, details=details)


class ConnectionError(CipherRunError):
    """Network connection error."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details=details)


class ValidationError(CipherRunError):
    """Data validation error."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=422, details=details)


class WebSocketError(CipherRunError):
    """WebSocket connection or communication error."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details=details)


def handle_http_error(status_code: int, error_data: Dict[str, Any]) -> CipherRunError:
    """Convert HTTP error response to appropriate exception.

    Args:
        status_code: HTTP status code
        error_data: Error response data

    Returns:
        Appropriate CipherRunError subclass
    """
    message = error_data.get("message", "Unknown error")
    details = error_data.get("details")

    error_map = {
        400: BadRequestError,
        401: UnauthorizedError,
        403: ForbiddenError,
        404: NotFoundError,
        408: TimeoutError,
        409: ConflictError,
        422: ValidationError,
        500: InternalServerError,
        503: ServiceUnavailableError,
    }

    if status_code == 429:
        return RateLimitError(message, details=details)

    error_class = error_map.get(status_code, APIError)
    return error_class(message, details=details)
