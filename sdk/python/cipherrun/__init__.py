"""CipherRun Python SDK.

A comprehensive Python SDK for the CipherRun SSL/TLS security scanning API.

This SDK provides both synchronous and asynchronous clients, WebSocket support
for real-time progress streaming, and full type hints with Pydantic models.

Example (Synchronous):
    >>> from cipherrun import CipherRunClient, ScanOptions
    >>>
    >>> client = CipherRunClient(api_key="your-api-key")
    >>> scan = client.create_scan("example.com:443", ScanOptions.full())
    >>> results = client.wait_for_scan(scan.scan_id)
    >>> print(f"Grade: {results.rating.grade}")

Example (Asynchronous):
    >>> import asyncio
    >>> from cipherrun import AsyncCipherRunClient, ScanOptions
    >>>
    >>> async def main():
    ...     async with AsyncCipherRunClient(api_key="your-api-key") as client:
    ...         scan = await client.create_scan("example.com:443", ScanOptions.full())
    ...         results = await client.wait_for_scan(scan.scan_id)
    ...         print(f"Grade: {results.rating.grade}")
    >>>
    >>> asyncio.run(main())

Example (WebSocket Progress):
    >>> from cipherrun import WebSocketProgressClient
    >>>
    >>> async def monitor_scan(scan_id: str):
    ...     async with WebSocketProgressClient() as ws_client:
    ...         async for progress in ws_client.stream_progress(scan_id):
    ...             print(f"Progress: {progress.progress}% - {progress.stage}")
"""

__version__ = "1.0.0"
__author__ = "CipherRun Team"
__license__ = "MIT"

from .client import CipherRunClient
from .async_client import AsyncCipherRunClient
from .websocket import WebSocketProgressClient, stream_progress_sync
from .models import (
    ScanOptions,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanStatusResponse,
    ScanResults,
    ProgressMessage,
    CertificateSummary,
    CertificateListResponse,
    PolicyRequest,
    PolicyResponse,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    ComplianceReport,
    HealthResponse,
    StatsResponse,
    ScanHistoryResponse,
    Severity,
    SecurityGrade,
    ProtocolTestResult,
    CipherInfo,
    VulnerabilityResult,
    CertificateAnalysisResult,
    HeaderAnalysisResult,
    RatingResult,
)
from .exceptions import (
    CipherRunError,
    APIError,
    BadRequestError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    RateLimitError,
    InternalServerError,
    ServiceUnavailableError,
    TimeoutError,
    ConnectionError,
    ValidationError,
    WebSocketError,
)

__all__ = [
    # Version
    "__version__",
    # Clients
    "CipherRunClient",
    "AsyncCipherRunClient",
    "WebSocketProgressClient",
    "stream_progress_sync",
    # Models - Requests
    "ScanOptions",
    "ScanRequest",
    "PolicyRequest",
    "PolicyEvaluationRequest",
    # Models - Responses
    "ScanResponse",
    "ScanStatusResponse",
    "ScanResults",
    "ProgressMessage",
    "CertificateSummary",
    "CertificateListResponse",
    "PolicyResponse",
    "PolicyEvaluationResponse",
    "ComplianceReport",
    "HealthResponse",
    "StatsResponse",
    "ScanHistoryResponse",
    # Models - Enums
    "ScanStatus",
    "Severity",
    "SecurityGrade",
    # Models - Results
    "ProtocolTestResult",
    "CipherInfo",
    "VulnerabilityResult",
    "CertificateAnalysisResult",
    "HeaderAnalysisResult",
    "RatingResult",
    # Exceptions
    "CipherRunError",
    "APIError",
    "BadRequestError",
    "UnauthorizedError",
    "ForbiddenError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "InternalServerError",
    "ServiceUnavailableError",
    "TimeoutError",
    "ConnectionError",
    "ValidationError",
    "WebSocketError",
]
