"""Tests for CipherRun SDK error-handling robustness.

These cover bugs fixed in client.py / async_client.py:

1. ``Retry-After`` parsing must not raise on the HTTP-date form (RFC 7231
   permits delta-seconds OR HTTP-date). Previously a bare ``int(...)`` raised
   an uncaught ``ValueError`` that escaped the SDK's ``CipherRunError``
   contract.
2. ``wait_for_scan`` must raise a ``CipherRunError`` subclass (``APIError``)
   on failed/cancelled scans, not a bare ``Exception`` (its docstring claims
   ``BadRequestError``/``CipherRunError``).
3. A non-JSON error body (e.g. an HTML 500 page) must not mask the real HTTP
   status as a generic connection error.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from cipherrun.async_client import (
    AsyncCipherRunClient,
)
from cipherrun.async_client import (
    _join_url as async_join_url,
)
from cipherrun.async_client import (
    _parse_retry_after as async_parse_retry_after,
)
from cipherrun.async_client import (
    _safe_error_data as async_safe_error_data,
)
from cipherrun.client import (
    CipherRunClient,
    _join_url,
    _parse_retry_after,
    _safe_error_data,
)
from cipherrun.exceptions import APIError, CipherRunError, RateLimitError
from cipherrun.models import ScanStatusResponse
from cipherrun.websocket import WebSocketProgressClient, _websocket_header_kwargs


def test_parse_retry_after_accepts_delta_seconds():
    assert _parse_retry_after("10") == 10
    assert _parse_retry_after("0", default=7) == 7  # non-positive falls back
    assert _parse_retry_after("-3", default=7) == 7


def test_parse_retry_after_accepts_http_date():
    # RFC 7231 allows an HTTP-date. A bare int() would raise ValueError here.
    assert _parse_retry_after("Wed, 21 Oct 2025 07:28:00 GMT", default=5) == 5


def test_parse_retry_after_handles_missing_and_garbage():
    assert _parse_retry_after(None) == 5
    assert _parse_retry_after(None, default=9) == 9
    assert _parse_retry_after("") == 5
    assert _parse_retry_after("not-a-number") == 5
    assert async_parse_retry_after("Wed, 21 Oct 2025 07:28:00 GMT") == 5


def test_safe_error_data_returns_empty_for_invalid_json():
    response = MagicMock()
    response.content = b"<html>Internal Server Error</html>"
    response.json = MagicMock(side_effect=ValueError("not json"))
    assert _safe_error_data(response) == {}


def test_safe_error_data_parses_valid_json():
    response = MagicMock()
    response.content = b'{"message": "boom"}'
    response.json = MagicMock(return_value={"message": "boom"})
    assert _safe_error_data(response) == {"message": "boom"}


def test_safe_error_data_empty_body():
    response = MagicMock()
    response.content = b""
    response.json = MagicMock(return_value={})
    assert _safe_error_data(response) == {}


def _failed_status(status: str, error: str = "something broke") -> ScanStatusResponse:
    return ScanStatusResponse(
        scan_id="scan-1",
        status=status,
        progress=100,
        error=error if status == "failed" else None,
    )


def test_wait_for_scan_failed_raises_api_error_not_bare_exception(monkeypatch):
    client = CipherRunClient(api_key="k")
    monkeypatch.setattr(client, "get_scan_status", lambda _sid: _failed_status("failed"))
    with pytest.raises(APIError) as exc:
        client.wait_for_scan("scan-1", poll_interval=0, timeout=5)
    assert "Scan failed" in str(exc.value)
    # Must be catchable as the base CipherRunError (the SDK contract).
    with pytest.raises(CipherRunError):
        client.wait_for_scan("scan-1", poll_interval=0, timeout=5)


def test_wait_for_scan_cancelled_raises_api_error(monkeypatch):
    client = CipherRunClient(api_key="k")
    monkeypatch.setattr(client, "get_scan_status", lambda _sid: _failed_status("cancelled"))
    with pytest.raises(APIError):
        client.wait_for_scan("scan-1", poll_interval=0, timeout=5)


def test_rate_limit_retry_does_not_crash_on_http_date_retry_after(monkeypatch):
    """A 429 with an HTTP-date Retry-After must retry, not raise ValueError."""
    client = CipherRunClient(api_key="k")

    call_count = {"n": 0}

    class FakeResponse:
        status_code = 429
        content = b""
        headers = {"Retry-After": "Wed, 21 Oct 2025 07:28:00 GMT"}

        def json(self):
            return {}

    def fake_request(*a, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return FakeResponse()
        # Second call: success.
        ok = MagicMock()
        ok.ok = True
        ok.status_code = 200
        ok.json = MagicMock(return_value={"scan_id": "x", "status": "queued"})
        return ok

    monkeypatch.setattr(client.session, "request", fake_request)
    monkeypatch.setattr("time.sleep", lambda *_a, **_kw: None)

    response = client._make_request("GET", "/api/v1/scan/x")
    assert response.status_code == 200
    assert call_count["n"] == 2


def test_rate_limit_exhausted_raises_rate_limit_error_not_value_error(monkeypatch):
    client = CipherRunClient(api_key="k")

    class FakeResponse:
        status_code = 429
        content = b""
        headers = {"Retry-After": "Wed, 21 Oct 2025 07:28:00 GMT"}

        def json(self):
            return {"message": "slow down"}

    monkeypatch.setattr(client.session, "request", lambda *a, **kw: FakeResponse())
    monkeypatch.setattr("time.sleep", lambda *_a, **_kw: None)

    with pytest.raises(RateLimitError):
        client._make_request("GET", "/api/v1/scan/x", max_rate_limit_retries=0)


def test_sync_client_quotes_path_parameters(monkeypatch):
    client = CipherRunClient(api_key="k")
    endpoints = []

    def fake_request(_method, endpoint, **_kwargs):
        endpoints.append(endpoint)
        response = MagicMock()
        response.json.return_value = {
            "scan_id": "scan/1",
            "status": "queued",
            "progress": 0,
        }
        return response

    monkeypatch.setattr(client, "_make_request", fake_request)

    client.get_scan_status("scan/1")

    assert endpoints == ["/api/v1/scan/scan%2F1"]


def test_join_url_preserves_base_path_prefix():
    assert _join_url("https://example.com/cipherrun", "/api/v1/health") == "https://example.com/cipherrun/api/v1/health"
    assert (
        async_join_url("https://example.com/cipherrun/", "api/v1/health")
        == "https://example.com/cipherrun/api/v1/health"
    )


# --- Async variants ---


def test_async_safe_error_data_invalid_json():
    response = AsyncMock()
    response.json = AsyncMock(side_effect=ValueError("not json"))
    assert asyncio.run(async_safe_error_data(response)) == {}


def test_async_safe_error_data_valid_json():
    response = AsyncMock()
    response.json = AsyncMock(return_value={"message": "boom"})
    assert asyncio.run(async_safe_error_data(response)) == {"message": "boom"}


def test_async_wait_for_scan_failed_raises_api_error(monkeypatch):
    client = AsyncCipherRunClient(api_key="k")

    async def fake_status(_sid):
        return _failed_status("failed")

    monkeypatch.setattr(client, "get_scan_status", fake_status)

    async def run():
        await client.wait_for_scan("scan-1", poll_interval=0, timeout=5)

    with pytest.raises(APIError):
        asyncio.run(run())


def test_async_client_quotes_path_parameters(monkeypatch):
    client = AsyncCipherRunClient(api_key="k")
    endpoints = []

    async def fake_request(_method, endpoint, **_kwargs):
        endpoints.append(endpoint)
        return {
            "scan_id": "scan/1",
            "status": "queued",
            "progress": 0,
        }

    monkeypatch.setattr(client, "_make_request", fake_request)

    async def run():
        await client.get_scan_status("scan/1")

    asyncio.run(run())

    assert endpoints == ["/api/v1/scan/scan%2F1"]


def test_websocket_client_quotes_scan_id_and_preserves_base_path(monkeypatch):
    connected_urls = []

    class FakeWebSocket:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def recv(self):
            return (
                '{"msg_type":"completed","scan_id":"scan/1","progress":100,'
                '"stage":"done","timestamp":"2026-01-01T00:00:00Z"}'
            )

    def fake_connect(url, **_kwargs):
        connected_urls.append(url)
        return FakeWebSocket()

    monkeypatch.setattr("websockets.connect", fake_connect)

    async def run():
        client = WebSocketProgressClient(base_url="http://localhost:8080/cipherrun")
        messages = []
        async for progress in client.stream_progress("scan/1"):
            messages.append(progress)
        return messages

    messages = asyncio.run(run())

    assert connected_urls == ["ws://localhost:8080/cipherrun/api/v1/scan/scan%2F1/stream"]
    assert messages[0].scan_id == "scan/1"


def test_websocket_header_kwargs_supports_old_websockets():
    def connect(_uri, *, extra_headers=None):
        return extra_headers

    assert _websocket_header_kwargs(connect, {"X-API-Key": "k"}) == {"extra_headers": {"X-API-Key": "k"}}


def test_websocket_header_kwargs_supports_new_websockets():
    def connect(_uri, *, additional_headers=None):
        return additional_headers

    assert _websocket_header_kwargs(connect, {"X-API-Key": "k"}) == {"additional_headers": {"X-API-Key": "k"}}


# --- SecurityGrade / RatingResult Unverified ---


def test_rating_result_accepts_unverified_grade():
    """The Rust API can return grade "Unverified" (cert could not be retrieved).

    The SDK's SecurityGrade enum previously lacked that variant, so parsing a
    rating with grade "Unverified" raised a pydantic ValidationError.
    """
    from cipherrun.models import RatingResult, SecurityGrade

    result = RatingResult(
        grade="Unverified",
        score=0,
        certificate_score=0,
        protocol_score=0,
        key_exchange_score=0,
        cipher_strength_score=0,
    )
    assert result.grade == SecurityGrade.UNVERIFIED
    assert result.grade == "Unverified"


def test_scan_results_accepts_rust_serialized_result_groups():
    """Rust serializes grouped optional results, not the SDK's flat aliases."""
    from cipherrun.models import ScanResults, SecurityGrade, Severity

    results = ScanResults(
        target="example.com:443",
        scan_time_ms=123,
        protocols=[
            {
                "protocol": "TLS 1.2",
                "supported": False,
                "inconclusive": True,
                "preferred": False,
                "ciphers_count": 0,
                "handshake_time_ms": None,
                "heartbeat_enabled": None,
                "session_resumption_caching": None,
                "session_resumption_tickets": None,
                "secure_renegotiation": None,
            }
        ],
        ciphers={},
        http={
            "http_headers": {
                "grade": "A",
                "score": 95,
                "issues": [],
                "http_status_code": 200,
                "server_hostname": "example.com",
            }
        },
        vulnerabilities=[
            {
                "vuln_type": "Heartbleed",
                "vulnerable": False,
                "inconclusive": True,
                "details": "probe timed out",
                "cve": None,
                "cwe": "CWE-200",
                "severity": "High",
            }
        ],
        advanced={
            "client_simulations": [
                {
                    "client_name": "OpenSSL",
                    "success": True,
                    "protocol": "TLS 1.2",
                    "cipher": None,
                    "error": None,
                    "handshake_time_ms": 20,
                }
            ]
        },
        rating={
            "ssl_rating": {
                "grade": "Unverified",
                "score": 0,
                "certificate_score": 0,
                "protocol_score": 0,
                "key_exchange_score": 0,
                "cipher_strength_score": 0,
                "warnings": ["certificate unavailable"],
            }
        },
    )

    assert results.protocols[0].inconclusive is True
    assert results.protocols[0].session_resumption_tickets is None
    assert results.vulnerabilities[0].inconclusive is True
    assert results.vulnerabilities[0].severity == Severity.HIGH
    assert results.vulnerabilities[0].cwe == "CWE-200"
    assert results.http_headers is not None
    assert results.http_headers.score == 95
    assert results.rating is not None
    assert results.rating.grade == SecurityGrade.UNVERIFIED
    assert results.client_simulations is not None
    assert results.client_simulations[0].client_name == "OpenSSL"
