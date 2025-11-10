"""CipherRun asynchronous HTTP client.

This module provides an async client for the CipherRun API using aiohttp.
"""

import asyncio
from typing import Optional, Dict, Any
from urllib.parse import urljoin

import aiohttp
from aiohttp import ClientTimeout

from .models import (
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
    ScanResults,
    ScanOptions,
    CertificateListResponse,
    CertificateSummary,
    ComplianceReport,
    PolicyRequest,
    PolicyResponse,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    ScanHistoryResponse,
    StatsResponse,
    HealthResponse,
)
from .exceptions import (
    handle_http_error,
    TimeoutError as SDKTimeoutError,
    ConnectionError as SDKConnectionError,
)


class AsyncCipherRunClient:
    """Asynchronous client for the CipherRun API.

    This client provides async methods for all CipherRun API endpoints with
    automatic retry logic, rate limit handling, and proper error handling.

    Args:
        base_url: Base URL of the CipherRun API (default: http://localhost:8080)
        api_key: API key for authentication (optional)
        timeout: Default timeout in seconds for requests (default: 30)
        max_retries: Maximum number of retries for failed requests (default: 3)
        retry_backoff: Exponential backoff factor for retries (default: 2.0)

    Example:
        >>> async with AsyncCipherRunClient(api_key="your-api-key") as client:
        ...     scan = await client.create_scan("example.com:443", ScanOptions.full())
        ...     print(f"Scan ID: {scan.scan_id}")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_backoff: float = 2.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff

        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "CipherRun-Python-SDK-Async/1.0.0",
            }
            if self.api_key:
                headers["X-API-Key"] = self.api_key

            timeout_obj = ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout_obj,
            )

        return self._session

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        retry_on_rate_limit: bool = True,
        max_rate_limit_retries: int = 3,
    ) -> Dict[str, Any]:
        """Make async HTTP request with error handling and rate limit retry.

        Args:
            method: HTTP method
            endpoint: API endpoint path
            json_data: JSON request body
            params: Query parameters
            timeout: Request timeout (uses default if None)
            retry_on_rate_limit: Whether to retry on rate limit errors
            max_rate_limit_retries: Maximum retries for rate limit errors

        Returns:
            Response data as dictionary

        Raises:
            CipherRunError: On API errors
        """
        url = urljoin(self.base_url, endpoint)
        session = await self._get_session()

        timeout_obj = ClientTimeout(total=timeout or self.timeout)
        rate_limit_retries = 0
        retry_count = 0

        while retry_count <= self.max_retries:
            try:
                async with session.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                    timeout=timeout_obj,
                ) as response:
                    if response.status == 429 and retry_on_rate_limit:
                        if rate_limit_retries >= max_rate_limit_retries:
                            error_data = await response.json() if response.content_length else {}
                            raise handle_http_error(response.status, error_data)

                        retry_after = int(response.headers.get("Retry-After", 5))
                        rate_limit_retries += 1
                        await asyncio.sleep(retry_after)
                        continue

                    if response.status >= 400:
                        error_data = await response.json() if response.content_length else {}
                        raise handle_http_error(response.status, error_data)

                    return await response.json()

            except asyncio.TimeoutError as e:
                if retry_count >= self.max_retries:
                    raise SDKTimeoutError(f"Request timed out after {timeout or self.timeout}s: {str(e)}")
                retry_count += 1
                await asyncio.sleep(self.retry_backoff ** retry_count)

            except aiohttp.ClientConnectionError as e:
                if retry_count >= self.max_retries:
                    raise SDKConnectionError(f"Connection failed: {str(e)}")
                retry_count += 1
                await asyncio.sleep(self.retry_backoff ** retry_count)

            except aiohttp.ClientError as e:
                raise SDKConnectionError(f"Request failed: {str(e)}")

    async def create_scan(
        self,
        target: str,
        options: Optional[ScanOptions] = None,
        webhook_url: Optional[str] = None,
    ) -> ScanResponse:
        """Create a new scan job.

        Args:
            target: Target to scan (hostname:port or just hostname)
            options: Scan options (uses default if None)
            webhook_url: Optional webhook URL to call when scan completes

        Returns:
            ScanResponse with scan ID and status

        Example:
            >>> scan = await client.create_scan("example.com:443", ScanOptions.full())
            >>> print(scan.scan_id)
        """
        request = ScanRequest(
            target=target,
            options=options or ScanOptions(),
            webhook_url=webhook_url,
        )
        data = await self._make_request("POST", "/api/v1/scan", json_data=request.model_dump())
        return ScanResponse(**data)

    async def get_scan_status(self, scan_id: str) -> ScanStatusResponse:
        """Get the status of a scan.

        Args:
            scan_id: Scan ID

        Returns:
            ScanStatusResponse with current status and progress

        Example:
            >>> status = await client.get_scan_status(scan_id)
            >>> print(f"Progress: {status.progress}%")
        """
        data = await self._make_request("GET", f"/api/v1/scan/{scan_id}")
        return ScanStatusResponse(**data)

    async def get_scan_results(self, scan_id: str) -> ScanResults:
        """Get the results of a completed scan.

        Args:
            scan_id: Scan ID

        Returns:
            ScanResults with complete scan data

        Raises:
            BadRequestError: If scan is not completed yet

        Example:
            >>> results = await client.get_scan_results(scan_id)
            >>> print(f"Protocols: {len(results.protocols)}")
        """
        data = await self._make_request("GET", f"/api/v1/scan/{scan_id}/results")
        return ScanResults(**data)

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a queued or running scan.

        Args:
            scan_id: Scan ID

        Returns:
            True if scan was cancelled successfully

        Example:
            >>> if await client.cancel_scan(scan_id):
            ...     print("Scan cancelled")
        """
        data = await self._make_request("DELETE", f"/api/v1/scan/{scan_id}")
        return "cancelled" in data.get("message", "").lower()

    async def wait_for_scan(
        self,
        scan_id: str,
        poll_interval: int = 5,
        timeout: int = 300,
    ) -> ScanResults:
        """Wait for a scan to complete and return results.

        Args:
            scan_id: Scan ID
            poll_interval: Seconds between status checks (default: 5)
            timeout: Maximum time to wait in seconds (default: 300)

        Returns:
            ScanResults when scan completes

        Raises:
            TimeoutError: If scan doesn't complete within timeout
            BadRequestError: If scan fails

        Example:
            >>> scan = await client.create_scan("example.com:443")
            >>> results = await client.wait_for_scan(scan.scan_id)
        """
        start_time = asyncio.get_event_loop().time()

        while True:
            if asyncio.get_event_loop().time() - start_time > timeout:
                raise SDKTimeoutError(f"Scan did not complete within {timeout}s")

            status = await self.get_scan_status(scan_id)

            if status.status == "completed":
                return await self.get_scan_results(scan_id)
            elif status.status == "failed":
                raise Exception(f"Scan failed: {status.error}")
            elif status.status == "cancelled":
                raise Exception("Scan was cancelled")

            await asyncio.sleep(poll_interval)

    async def list_certificates(
        self,
        hostname: Optional[str] = None,
        expiring_within_days: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "expiry_asc",
    ) -> CertificateListResponse:
        """List certificates from the inventory.

        Args:
            hostname: Filter by hostname (optional)
            expiring_within_days: Filter by expiring within days (optional)
            limit: Maximum number of results (default: 50)
            offset: Offset for pagination (default: 0)
            sort: Sort order (expiry_asc, expiry_desc, issued_asc, issued_desc)

        Returns:
            CertificateListResponse with paginated results

        Example:
            >>> certs = await client.list_certificates(expiring_within_days=30)
            >>> print(f"Found {certs.total} certificates")
        """
        params = {
            "limit": limit,
            "offset": offset,
            "sort": sort,
        }
        if hostname:
            params["hostname"] = hostname
        if expiring_within_days is not None:
            params["expiring_within_days"] = expiring_within_days

        data = await self._make_request("GET", "/api/v1/certificates", params=params)
        return CertificateListResponse(**data)

    async def get_certificate(self, fingerprint: str) -> CertificateSummary:
        """Get certificate details by fingerprint.

        Args:
            fingerprint: Certificate SHA-256 fingerprint

        Returns:
            CertificateSummary with certificate details

        Example:
            >>> cert = await client.get_certificate(fingerprint)
            >>> print(cert.common_name)
        """
        data = await self._make_request("GET", f"/api/v1/certificates/{fingerprint}")
        return CertificateSummary(**data)

    async def check_compliance(self, framework: str, target: str, detailed: bool = False) -> ComplianceReport:
        """Check compliance against a framework.

        Args:
            framework: Compliance framework (pci-dss-v4, nist-sp800-52r2, fedramp, hipaa)
            target: Target to check
            detailed: Generate detailed report

        Returns:
            ComplianceReport with compliance status

        Example:
            >>> report = await client.check_compliance("pci-dss-v4", "example.com:443")
            >>> print(report.status)
        """
        data = await self._make_request("GET", f"/api/v1/compliance/{framework}")
        return ComplianceReport(**data)

    async def create_policy(
        self,
        name: str,
        rules: str,
        description: Optional[str] = None,
        enabled: bool = True,
    ) -> PolicyResponse:
        """Create or update a policy.

        Args:
            name: Policy name
            rules: Policy rules in YAML format
            description: Policy description (optional)
            enabled: Whether policy is enabled (default: True)

        Returns:
            PolicyResponse with policy details

        Example:
            >>> policy = await client.create_policy(
            ...     name="My Policy",
            ...     rules="min_tls_version: '1.2'",
            ... )
        """
        request = PolicyRequest(
            name=name,
            description=description,
            rules=rules,
            enabled=enabled,
        )
        data = await self._make_request("POST", "/api/v1/policies", json_data=request.model_dump())
        return PolicyResponse(**data)

    async def get_policy(self, policy_id: str) -> PolicyResponse:
        """Get policy details.

        Args:
            policy_id: Policy ID

        Returns:
            PolicyResponse with policy details

        Example:
            >>> policy = await client.get_policy(policy_id)
            >>> print(policy.name)
        """
        data = await self._make_request("GET", f"/api/v1/policies/{policy_id}")
        return PolicyResponse(**data)

    async def evaluate_policy(
        self,
        policy_id: str,
        target: str,
        options: Optional[ScanOptions] = None,
    ) -> PolicyEvaluationResponse:
        """Evaluate a target against a policy.

        Args:
            policy_id: Policy ID
            target: Target to evaluate
            options: Scan options (uses default if None)

        Returns:
            PolicyEvaluationResponse with evaluation results

        Example:
            >>> result = await client.evaluate_policy(policy_id, "example.com:443")
            >>> print(f"Compliant: {result.compliant}")
        """
        request = PolicyEvaluationRequest(
            target=target,
            options=options or ScanOptions(),
        )
        data = await self._make_request(
            "POST",
            f"/api/v1/policies/{policy_id}/evaluate",
            json_data=request.model_dump(),
        )
        return PolicyEvaluationResponse(**data)

    async def get_scan_history(
        self,
        hostname: str,
        port: int = 443,
        limit: int = 10,
    ) -> ScanHistoryResponse:
        """Get scan history for a target.

        Args:
            hostname: Target hostname
            port: Target port (default: 443)
            limit: Maximum number of records (default: 10)

        Returns:
            ScanHistoryResponse with historical scans

        Example:
            >>> history = await client.get_scan_history("example.com")
            >>> print(f"Total scans: {history.total_scans}")
        """
        params = {"hostname": hostname, "port": port, "limit": limit}
        data = await self._make_request("GET", "/api/v1/history", params=params)
        return ScanHistoryResponse(**data)

    async def get_api_stats(self) -> StatsResponse:
        """Get API usage statistics.

        Returns:
            StatsResponse with API statistics

        Example:
            >>> stats = await client.get_api_stats()
            >>> print(f"Total scans: {stats.total_scans}")
        """
        data = await self._make_request("GET", "/api/v1/stats")
        return StatsResponse(**data)

    async def health_check(self) -> HealthResponse:
        """Check API health status.

        Returns:
            HealthResponse with health status

        Example:
            >>> health = await client.health_check()
            >>> print(f"Status: {health.status}")
        """
        data = await self._make_request("GET", "/api/v1/health")
        return HealthResponse(**data)

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
