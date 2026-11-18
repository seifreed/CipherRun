"""Contract tests for the hand-written synchronous, async, and WebSocket SDK."""

import asyncio
import json
from unittest.mock import AsyncMock, Mock, patch

import pytest
import requests
import websockets
import aiohttp

import cipherrun.client as sync_module
import cipherrun.async_client as async_module
import cipherrun.websocket as websocket_module
from cipherrun.async_client import AsyncCipherRunClient
from cipherrun.client import CipherRunClient
from cipherrun.exceptions import (
    APIError,
    BadRequestError,
    CipherRunError,
    ConflictError,
    ConnectionError,
    ForbiddenError,
    InternalServerError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
    TimeoutError,
    UnauthorizedError,
    ValidationError,
    WebSocketError,
    handle_http_error,
)
from cipherrun.models import ComplianceReport, ScanOptions, ScanResults
from cipherrun.websocket import WebSocketProgressClient


def test_error_mapping_and_model_helpers():
    for status, error_type in [
        (400, BadRequestError), (401, UnauthorizedError), (403, ForbiddenError),
        (404, NotFoundError), (408, TimeoutError), (409, ConflictError),
        (422, ValidationError), (500, InternalServerError), (503, ServiceUnavailableError),
    ]:
        error = handle_http_error(status, {"error": "problem", "details": {"code": "x"}})
        assert isinstance(error, error_type)
        assert error.details == {"code": "x"}
        assert f"[{status}] problem" == str(error)

    assert str(handle_http_error(418, {})) == "Unknown error"
    assert str(handle_http_error(429, {"message": "slow", "retry_after": 5})) == "[429] slow (retry after 5s)"
    assert str(RateLimitError("slow", retry_after=0)) == "[429] slow"
    assert str(ConnectionError("offline")) == "offline"
    assert str(WebSocketError("closed")) == "closed"
    assert str(CipherRunError("generic", status_code=0)) == "generic"
    assert async_module._parse_retry_after(None) == 5
    assert async_module._parse_retry_after("") == 5

    assert ScanOptions.full().full_scan is True
    assert ScanOptions.quick().test_ciphers is False
    assert ScanResults._flatten_rust_result_groups("unchanged") == "unchanged"
    flattened = ScanResults._flatten_rust_result_groups({
        "http": {"http_headers": {"grade": "A"}},
        "rating": {"ssl_rating": {"grade": "A"}},
        "advanced": {"client_simulations": [{"name": "browser"}]},
    })
    assert flattened["http_headers"] == {"grade": "A"}
    assert flattened["rating"] == {"grade": "A"}
    assert flattened["client_simulations"] == [{"name": "browser"}]
    report = ComplianceReport.model_construct(framework_id="pci", status="compliant")
    assert report.framework == "pci"
    assert report.message is None


def _response(status=200, payload=None, headers=None):
    response = Mock()
    response.status_code = status
    response.status = status
    response.ok = status < 400
    response.headers = headers or {}
    response.json.return_value = payload or {}
    return response


def test_sync_request_errors_and_endpoint_wrappers(monkeypatch):
    client = CipherRunClient(base_url="https://api.example/base", api_key="secret")
    monkeypatch.setattr(client.session, "request", Mock(side_effect=requests.exceptions.Timeout("slow")))
    with pytest.raises(sync_module.SDKTimeoutError):
        client._make_request("GET", "/health")
    monkeypatch.setattr(client.session, "request", Mock(side_effect=requests.exceptions.ConnectionError("offline")))
    with pytest.raises(sync_module.SDKConnectionError):
        client._make_request("GET", "/health")
    monkeypatch.setattr(client.session, "request", Mock(side_effect=requests.exceptions.RequestException("bad request")))
    with pytest.raises(sync_module.SDKConnectionError, match="Request failed"):
        client._make_request("GET", "/health")
    error_response = _response(400, {"message": "invalid request"})
    error_response.content = b'{"message":"invalid request"}'
    monkeypatch.setattr(client.session, "request", Mock(return_value=error_response))
    with pytest.raises(BadRequestError, match="invalid request"):
        client._make_request("GET", "/health")

    routes = []

    def fake_request(method, endpoint, **kwargs):
        routes.append((method, endpoint, kwargs))
        return _response(payload={"message": "cancelled"})

    monkeypatch.setattr(client, "_make_request", fake_request)
    monkeypatch.setattr(sync_module, "ScanResponse", lambda **data: data)
    monkeypatch.setattr(sync_module, "ScanStatusResponse", lambda **data: data)
    monkeypatch.setattr(sync_module, "ScanResults", lambda **data: data)
    monkeypatch.setattr(sync_module, "CertificateListResponse", lambda **data: data)
    monkeypatch.setattr(sync_module, "CertificateSummary", lambda **data: data)
    monkeypatch.setattr(sync_module, "ComplianceReport", lambda **data: data)
    monkeypatch.setattr(sync_module, "PolicyResponse", lambda **data: data)
    monkeypatch.setattr(sync_module, "PolicyEvaluationResponse", lambda **data: data)
    monkeypatch.setattr(sync_module, "ScanHistoryResponse", lambda **data: data)
    monkeypatch.setattr(sync_module, "StatsResponse", lambda **data: data)
    monkeypatch.setattr(sync_module, "HealthResponse", lambda **data: data)

    client.create_scan("example.com")
    client.get_scan_status("scan/1")
    client.get_scan_results("scan/1")
    assert client.cancel_scan("scan/1") is True
    client.list_certificates(hostname="example.com", expiring_within_days=30)
    client.get_certificate("fingerprint/1")
    client.check_compliance("pci/dss", "example.com", detailed=True)
    client.create_policy("name", "rules")
    client.get_policy("policy/1")
    client.evaluate_policy("policy/1", "example.com")
    client.get_scan_history("example.com")
    client.get_api_stats()
    client.health_check()
    assert routes[1][1] == "/api/v1/scan/scan%2F1"
    assert routes[5][1] == "/api/v1/certificates/fingerprint%2F1"
    assert routes[6][2]["params"]["detailed"] == "true"

    with client as entered:
        assert entered is client
    client.__exit__(None, None, None)


def test_async_request_retries_errors_and_wrappers(monkeypatch):
    client = AsyncCipherRunClient(base_url="https://api.example/base", api_key="secret", max_retries=1)

    class ContextResponse:
        status = 200
        headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def json(self):
            return {"ok": True}

    class FakeSession:
        closed = False
        close = AsyncMock()

        def __init__(self, outcomes):
            self.outcomes = iter(outcomes)

        def request(self, **_kwargs):
            result = next(self.outcomes)
            if isinstance(result, Exception):
                error = result

                class FailedContext:
                    async def __aenter__(self):
                        raise error

                    async def __aexit__(self, *_):
                        return None

                return FailedContext()
            return result

    async def exercise_retries():
        client._session = FakeSession([asyncio.TimeoutError(), ContextResponse()])
        with patch.object(async_module.asyncio, "sleep", new=AsyncMock()):
            assert await client._make_request("GET", "/health") == {"ok": True}
        client._session = FakeSession([asyncio.TimeoutError(), asyncio.TimeoutError()])
        with patch.object(async_module.asyncio, "sleep", new=AsyncMock()):
            with pytest.raises(async_module.SDKTimeoutError):
                await client._make_request("GET", "/health")
        client._session = FakeSession([aiohttp.ClientConnectionError("offline"), ContextResponse()])
        with patch.object(async_module.asyncio, "sleep", new=AsyncMock()):
            assert await client._make_request("GET", "/health") == {"ok": True}
        client._session = FakeSession([
            aiohttp.ClientConnectionError("offline"),
            aiohttp.ClientConnectionError("offline"),
        ])
        with patch.object(async_module.asyncio, "sleep", new=AsyncMock()):
            with pytest.raises(async_module.SDKConnectionError):
                await client._make_request("GET", "/health")
        client._session = FakeSession([aiohttp.ClientError("protocol failure")])
        with pytest.raises(async_module.SDKConnectionError, match="Request failed"):
            await client._make_request("GET", "/health")

        class RateLimited(ContextResponse):
            status = 429
            headers = {"Retry-After": "1"}

        client._session = FakeSession([RateLimited(), ContextResponse()])
        with patch.object(async_module.asyncio, "sleep", new=AsyncMock()):
            assert await client._make_request("GET", "/health") == {"ok": True}
        client._session = FakeSession([RateLimited()])
        with pytest.raises(RateLimitError):
            await client._make_request("GET", "/health", max_rate_limit_retries=0)

        class BadRequest(ContextResponse):
            status = 400

            async def json(self):
                return {"message": "invalid"}

        client._session = FakeSession([BadRequest()])
        with pytest.raises(BadRequestError):
            await client._make_request("GET", "/health")

    asyncio.run(exercise_retries())

    routes = []

    async def fake_request(method, endpoint, **kwargs):
        routes.append((method, endpoint, kwargs))
        return {"message": "cancelled"}

    monkeypatch.setattr(client, "_make_request", fake_request)
    for name in (
        "ScanResponse", "ScanStatusResponse", "ScanResults", "CertificateListResponse",
        "CertificateSummary", "ComplianceReport", "PolicyResponse", "PolicyEvaluationResponse",
        "ScanHistoryResponse", "StatsResponse", "HealthResponse",
    ):
        monkeypatch.setattr(async_module, name, lambda **data: data)

    async def exercise_wrappers():
        await client.create_scan("example.com")
        await client.get_scan_status("scan/1")
        await client.get_scan_results("scan/1")
        assert await client.cancel_scan("scan/1") is True
        await client.list_certificates(hostname="example.com", expiring_within_days=30)
        await client.get_certificate("fingerprint/1")
        await client.check_compliance("pci/dss", "example.com", detailed=True)
        await client.create_policy("name", "rules")
        await client.get_policy("policy/1")
        await client.evaluate_policy("policy/1", "example.com")
        await client.get_scan_history("example.com")
        await client.get_api_stats()
        await client.health_check()
        async with client as entered:
            assert entered is client
        await client.__aexit__(None, None, None)

    asyncio.run(exercise_wrappers())
    assert routes[1][1] == "/api/v1/scan/scan%2F1"
    assert routes[5][1] == "/api/v1/certificates/fingerprint%2F1"
    assert routes[6][2]["params"]["detailed"] == "true"


def test_async_session_is_created_and_reopened_with_credentials(monkeypatch):
    made = []

    class Session:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.closed = False
            self.close_count = 0
            made.append(self)

        async def close(self):
            self.closed = True
            self.close_count += 1

    monkeypatch.setattr(async_module.aiohttp, "ClientSession", Session)
    client = AsyncCipherRunClient(api_key="secret", timeout=9)

    async def get_sessions():
        first = await client._get_session()
        assert await client._get_session() is first
        first.closed = True
        second = await client._get_session()
        assert second is not first
        assert await client._get_session() is second
        await client.close()
        await client.close()
        return first, second

    first, second = asyncio.run(get_sessions())
    assert first.kwargs["headers"]["X-API-Key"] == "secret"
    assert first.kwargs["timeout"].total == 9
    assert second.close_count == 1


def test_sync_and_async_scan_wait_results_and_stops(monkeypatch):
    sync = CipherRunClient()
    sync_statuses = iter([Mock(status="running"), Mock(status="completed")])
    monkeypatch.setattr(sync, "get_scan_status", lambda _scan: next(sync_statuses))
    monkeypatch.setattr(sync, "get_scan_results", lambda _scan: "scan-results")
    monkeypatch.setattr(sync_module.time, "sleep", lambda _seconds: None)
    assert sync.wait_for_scan("s", poll_interval=1) == "scan-results"

    monkeypatch.setattr(sync, "get_scan_status", lambda _scan: Mock(status="completed"))
    assert sync.wait_for_scan("s", poll_interval=0) == "scan-results"
    monkeypatch.setattr(sync, "get_scan_status", lambda _scan: Mock(status="cancelled"))
    with pytest.raises(APIError, match="cancelled"):
        sync.wait_for_scan("s", poll_interval=0)
    with pytest.raises(sync_module.SDKTimeoutError):
        sync.wait_for_scan("s", timeout=-1)

    async_client = AsyncCipherRunClient()

    async def completed(_scan):
        return Mock(status="completed")

    async def results(_scan):
        return "async-results"

    monkeypatch.setattr(async_client, "get_scan_status", completed)
    monkeypatch.setattr(async_client, "get_scan_results", results)

    async def run():
        assert await async_client.wait_for_scan("s", poll_interval=0) == "async-results"
        statuses = iter([Mock(status="running"), Mock(status="completed")])

        async def running_then_completed(_scan):
            return next(statuses)

        async_client.get_scan_status = running_then_completed
        with patch.object(async_module.asyncio, "sleep", new=AsyncMock()):
            assert await async_client.wait_for_scan("s", poll_interval=1) == "async-results"

        async def cancelled(_scan):
            return Mock(status="cancelled")
        async_client.get_scan_status = cancelled
        with pytest.raises(APIError, match="cancelled"):
            await async_client.wait_for_scan("s", poll_interval=0)
        with pytest.raises(async_module.SDKTimeoutError):
            await async_client.wait_for_scan("s", timeout=-1)

    asyncio.run(run())


def test_websocket_frames_lifecycle_and_error_paths(monkeypatch):
    from cipherrun.models import ProgressMessage
    from websockets.exceptions import ConnectionClosed
    from websockets.frames import Close

    with pytest.raises(WebSocketError, match="Progress stream fell behind"):
        websocket_module._progress_message_from_frame({"type": "lagged"})
    with pytest.raises(WebSocketError, match="Unexpected WebSocket message"):
        websocket_module._progress_message_from_frame({"type": "unknown"})
    with pytest.raises(WebSocketError, match="Invalid progress message"):
        websocket_module._progress_message_from_frame({"msg_type": "progress"})
    assert websocket_module._progress_message_from_frame({"type": "connected"}) is None
    assert WebSocketProgressClient()._convert_to_ws_url("https://api.example/base") == "wss://api.example/base"

    class FakeSocket:
        closed = False

        def __init__(self, messages):
            self.messages = iter(messages)
            self.close = AsyncMock()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def recv(self):
            return next(self.messages)

    socket = FakeSocket([
        '{"type":"connected"}',
        '{"msg_type":"progress","scan_id":"s","progress":50,"stage":"testing","timestamp":"2026-01-01T00:00:00Z"}',
        '{"msg_type":"completed","scan_id":"s","progress":100,"stage":"done","timestamp":"2026-01-01T00:00:01Z"}',
    ])
    calls = []
    monkeypatch.setattr("websockets.connect", lambda url, **kwargs: (calls.append((url, kwargs)) or socket))

    async def stream():
        client = WebSocketProgressClient("https://api.example/base/", api_key="secret")
        messages = [message async for message in client.stream_progress("s")]
        assert client._websocket is None
        return client, messages

    client, messages = asyncio.run(stream())
    assert [message.progress for message in messages] == [50, 100]
    assert calls[0][0] == "wss://api.example/base/api/v1/scan/s/stream"
    assert calls[0][1].get("additional_headers", calls[0][1].get("extra_headers")) == {"X-API-Key": "secret"}

    async def callbacks():
        seen = []
        client = WebSocketProgressClient()

        async def progress_messages(_scan_id, _timeout):
            yield ProgressMessage(msg_type="completed", scan_id="s", progress=100, stage="done", timestamp="2026-01-01T00:00:00Z")

        client.stream_progress = progress_messages
        await client.stream_progress_with_callback("s", lambda message: _callback(seen, message))
        client._websocket = socket
        await client.close()
        assert seen and socket.close.await_count == 1
        await client.__aenter__()
        await client.__aexit__(None, None, None)

    async def _callback(seen, message):
        seen.append(message)

    asyncio.run(callbacks())

    def socket_failure(*_args, **_kwargs):
        raise OSError("connection failed")

    monkeypatch.setattr("websockets.connect", socket_failure)

    async def failed_connection():
        async for _ in WebSocketProgressClient().stream_progress("s"):
            pass

    with pytest.raises(websocket_module.SDKConnectionError):
        asyncio.run(failed_connection())

    def websocket_failure(*_args, **_kwargs):
        raise websockets.exceptions.WebSocketException("bad handshake")

    monkeypatch.setattr("websockets.connect", websocket_failure)
    with pytest.raises(WebSocketError, match="WebSocket error"):
        asyncio.run(failed_connection())

    monkeypatch.setattr("websockets.connect", lambda *_args, **_kwargs: FakeSocket(["invalid json"]))
    with pytest.raises(WebSocketError, match="Invalid WebSocket JSON frame"):
        asyncio.run(failed_connection())

    monkeypatch.setattr("websockets.connect", lambda *_args, **_kwargs: FakeSocket([]))
    async def timed_out_recv():
        async for _ in WebSocketProgressClient().stream_progress("s", timeout=0):
            pass
    with pytest.raises(WebSocketError, match="timeout"):
        asyncio.run(timed_out_recv())

    class ClosedSocket(FakeSocket):
        async def recv(self):
            raise ConnectionClosed(Close(1000, "closed"), None)

    monkeypatch.setattr("websockets.connect", lambda *_args, **_kwargs: ClosedSocket([]))
    with pytest.raises(WebSocketError, match="WebSocket connection closed"):
        asyncio.run(failed_connection())


def test_websocket_sync_helper_returns_async_iterator(monkeypatch):
    iterator = object()
    client = Mock()
    client.stream_progress.return_value = iterator
    monkeypatch.setattr(websocket_module, "WebSocketProgressClient", Mock(return_value=client))
    assert websocket_module.stream_progress_sync("https://api.example", "scan", "key", 2) is iterator
    client.stream_progress.assert_called_once_with("scan", 2)
