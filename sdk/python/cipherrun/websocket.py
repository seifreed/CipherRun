"""CipherRun WebSocket client for real-time progress streaming.

This module provides WebSocket client functionality for streaming scan progress.
"""

import asyncio
import json
from typing import AsyncIterator, Optional, Callable, Awaitable
from urllib.parse import urljoin, urlparse

import websockets
from websockets.client import WebSocketClientProtocol

from .models import ProgressMessage
from .exceptions import WebSocketError, ConnectionError as SDKConnectionError


class WebSocketProgressClient:
    """WebSocket client for streaming scan progress updates.

    This client connects to the CipherRun WebSocket endpoint and streams
    real-time progress updates for a specific scan.

    Args:
        base_url: Base URL of the CipherRun API (default: http://localhost:8080)
        api_key: API key for authentication (optional)

    Example:
        >>> async with WebSocketProgressClient() as ws_client:
        ...     async for progress in ws_client.stream_progress(scan_id):
        ...         print(f"Progress: {progress.progress}% - {progress.stage}")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._websocket: Optional[WebSocketClientProtocol] = None

    def _convert_to_ws_url(self, http_url: str) -> str:
        """Convert HTTP/HTTPS URL to WS/WSS URL.

        Args:
            http_url: HTTP or HTTPS URL

        Returns:
            Corresponding WS or WSS URL
        """
        parsed = urlparse(http_url)
        if parsed.scheme == "https":
            ws_scheme = "wss"
        else:
            ws_scheme = "ws"

        return f"{ws_scheme}://{parsed.netloc}{parsed.path}"

    async def stream_progress(
        self,
        scan_id: str,
        timeout: int = 300,
    ) -> AsyncIterator[ProgressMessage]:
        """Stream progress updates for a scan via WebSocket.

        Args:
            scan_id: Scan ID to monitor
            timeout: Connection timeout in seconds (default: 300)

        Yields:
            ProgressMessage objects with scan progress

        Raises:
            WebSocketError: On WebSocket connection errors

        Example:
            >>> async for progress in client.stream_progress(scan_id):
            ...     print(f"{progress.stage}: {progress.progress}%")
            ...     if progress.msg_type == "completed":
            ...         break
        """
        endpoint = f"/api/v1/scan/{scan_id}/stream"
        ws_url = self._convert_to_ws_url(urljoin(self.base_url, endpoint))

        extra_headers = {}
        if self.api_key:
            extra_headers["X-API-Key"] = self.api_key

        try:
            async with websockets.connect(
                ws_url,
                extra_headers=extra_headers,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=10,
            ) as websocket:
                self._websocket = websocket

                try:
                    while True:
                        try:
                            message = await asyncio.wait_for(
                                websocket.recv(),
                                timeout=timeout,
                            )

                            data = json.loads(message)
                            progress = ProgressMessage(**data)

                            yield progress

                            if progress.msg_type in ["completed", "failed", "cancelled"]:
                                break

                        except asyncio.TimeoutError:
                            raise WebSocketError(
                                f"No message received within {timeout}s timeout"
                            )

                except websockets.exceptions.ConnectionClosed as e:
                    raise WebSocketError(f"WebSocket connection closed: {e}")

        except websockets.exceptions.WebSocketException as e:
            raise WebSocketError(f"WebSocket error: {str(e)}")
        except Exception as e:
            raise SDKConnectionError(f"Connection failed: {str(e)}")
        finally:
            self._websocket = None

    async def stream_progress_with_callback(
        self,
        scan_id: str,
        callback: Callable[[ProgressMessage], Awaitable[None]],
        timeout: int = 300,
    ):
        """Stream progress updates with a callback function.

        Args:
            scan_id: Scan ID to monitor
            callback: Async callback function to handle each progress update
            timeout: Connection timeout in seconds (default: 300)

        Raises:
            WebSocketError: On WebSocket connection errors

        Example:
            >>> async def handle_progress(progress: ProgressMessage):
            ...     print(f"Progress: {progress.progress}%")
            >>> await client.stream_progress_with_callback(scan_id, handle_progress)
        """
        async for progress in self.stream_progress(scan_id, timeout):
            await callback(progress)

    async def close(self):
        """Close the WebSocket connection."""
        if self._websocket and not self._websocket.closed:
            await self._websocket.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()


def stream_progress_sync(
    base_url: str,
    scan_id: str,
    api_key: Optional[str] = None,
    timeout: int = 300,
) -> AsyncIterator[ProgressMessage]:
    """Convenience function to stream progress (for use with asyncio.run).

    Args:
        base_url: Base URL of the CipherRun API
        scan_id: Scan ID to monitor
        api_key: API key for authentication (optional)
        timeout: Connection timeout in seconds (default: 300)

    Returns:
        AsyncIterator of ProgressMessage objects

    Example:
        >>> async def main():
        ...     async for progress in stream_progress_sync("http://localhost:8080", scan_id):
        ...         print(f"Progress: {progress.progress}%")
        >>> asyncio.run(main())
    """
    client = WebSocketProgressClient(base_url=base_url, api_key=api_key)
    return client.stream_progress(scan_id, timeout)
