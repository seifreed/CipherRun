# CipherRun Python SDK

Official Python SDK for the CipherRun SSL/TLS security scanning API.

## Features

- **Synchronous and Asynchronous Clients**: Choose between `CipherRunClient` (sync) and `AsyncCipherRunClient` (async)
- **WebSocket Support**: Real-time progress streaming via WebSocket
- **Full Type Hints**: Complete type annotations with Pydantic v2 models
- **Automatic Retries**: Exponential backoff for failed requests
- **Rate Limit Handling**: Automatic retry with `Retry-After` header support
- **Comprehensive Error Handling**: Custom exceptions for all error cases
- **Production Ready**: Installable package ready for PyPI

## Installation

```bash
pip install cipherrun
```

Or install from source:

```bash
git clone https://github.com/yourusername/cipherrun.git
cd cipherrun/sdk/python
pip install -e .
```

## Quick Start

### Synchronous Client

```python
from cipherrun import CipherRunClient, ScanOptions

# Initialize client
client = CipherRunClient(
    base_url="http://localhost:8080",
    api_key="your-api-key"
)

# Create a full scan
scan = client.create_scan("example.com:443", ScanOptions.full())
print(f"Scan ID: {scan.scan_id}")

# Wait for scan to complete
results = client.wait_for_scan(scan.scan_id)
print(f"Grade: {results.rating.grade}")
print(f"Vulnerabilities: {len(results.vulnerabilities)}")

# Close client
client.close()
```

### Asynchronous Client

```python
import asyncio
from cipherrun import AsyncCipherRunClient, ScanOptions

async def main():
    # Use context manager for automatic cleanup
    async with AsyncCipherRunClient(api_key="your-api-key") as client:
        # Create scan
        scan = await client.create_scan("example.com:443", ScanOptions.full())

        # Wait for completion
        results = await client.wait_for_scan(scan.scan_id)

        print(f"Grade: {results.rating.grade}")
        print(f"Protocols tested: {len(results.protocols)}")

asyncio.run(main())
```

### WebSocket Progress Streaming

```python
import asyncio
from cipherrun import CipherRunClient, WebSocketProgressClient, ScanOptions

async def monitor_scan():
    # Create scan with sync client
    client = CipherRunClient()
    scan = client.create_scan("example.com:443", ScanOptions.full())

    # Monitor progress via WebSocket
    async with WebSocketProgressClient() as ws_client:
        async for progress in ws_client.stream_progress(scan.scan_id):
            print(f"[{progress.progress}%] {progress.stage}")

            if progress.msg_type == "completed":
                print("Scan completed!")
                break
            elif progress.msg_type == "failed":
                print(f"Scan failed: {progress.details}")
                break

    # Get final results
    results = client.get_scan_results(scan.scan_id)
    print(f"Final grade: {results.rating.grade}")

asyncio.run(monitor_scan())
```

## API Coverage

The SDK provides complete coverage of all CipherRun API endpoints:

### Scans
- `create_scan(target, options)` - Create a new scan
- `get_scan_status(scan_id)` - Get scan status and progress
- `get_scan_results(scan_id)` - Get complete scan results
- `cancel_scan(scan_id)` - Cancel a running scan
- `wait_for_scan(scan_id)` - Wait for scan completion

### Certificates
- `list_certificates(hostname, limit, offset)` - List certificates
- `get_certificate(fingerprint)` - Get certificate details

### Compliance
- `check_compliance(framework, target)` - Check compliance against frameworks

### Policies
- `create_policy(name, rules)` - Create a security policy
- `get_policy(policy_id)` - Get policy details
- `evaluate_policy(policy_id, target)` - Evaluate target against policy

### History & Stats
- `get_scan_history(hostname, port)` - Get historical scans
- `get_api_stats()` - Get API usage statistics
- `health_check()` - Check API health

## Scan Options

### Full Scan

```python
options = ScanOptions.full()
scan = client.create_scan("example.com:443", options)
```

### Quick Scan

```python
options = ScanOptions.quick()
scan = client.create_scan("example.com:443", options)
```

### Custom Options

```python
options = ScanOptions(
    test_protocols=True,
    test_ciphers=True,
    test_vulnerabilities=True,
    analyze_certificates=True,
    test_http_headers=True,
    client_simulation=False,
    timeout_seconds=30,
)
scan = client.create_scan("example.com:443", options)
```

## Error Handling

The SDK provides comprehensive error handling with custom exceptions:

```python
from cipherrun import (
    CipherRunClient,
    BadRequestError,
    UnauthorizedError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
)

client = CipherRunClient(api_key="your-api-key")

try:
    scan = client.create_scan("example.com:443")
    results = client.wait_for_scan(scan.scan_id, timeout=300)

except BadRequestError as e:
    print(f"Invalid request: {e.message}")

except UnauthorizedError:
    print("Invalid API key")

except NotFoundError as e:
    print(f"Resource not found: {e.message}")

except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")

except TimeoutError:
    print("Request timed out")

finally:
    client.close()
```

## Batch Scanning (Async)

```python
import asyncio
from cipherrun import AsyncCipherRunClient, ScanOptions

async def scan_multiple_targets():
    targets = [
        "example.com:443",
        "google.com:443",
        "github.com:443",
    ]

    async with AsyncCipherRunClient() as client:
        # Create all scans concurrently
        scans = await asyncio.gather(*[
            client.create_scan(target, ScanOptions.quick())
            for target in targets
        ])

        # Wait for all to complete
        results = await asyncio.gather(*[
            client.wait_for_scan(scan.scan_id)
            for scan in scans
        ])

        for target, result in zip(targets, results):
            print(f"{target}: Grade {result.rating.grade}")

asyncio.run(scan_multiple_targets())
```

## Advanced Usage

### Custom Base URL and Timeouts

```python
client = CipherRunClient(
    base_url="https://api.cipherrun.com",
    api_key="your-api-key",
    timeout=60,
    max_retries=5,
    retry_backoff=2.0,
)
```

### Using Context Managers

```python
# Synchronous
with CipherRunClient(api_key="key") as client:
    scan = client.create_scan("example.com:443")
    results = client.wait_for_scan(scan.scan_id)

# Asynchronous
async with AsyncCipherRunClient(api_key="key") as client:
    scan = await client.create_scan("example.com:443")
    results = await client.wait_for_scan(scan.scan_id)
```

### WebSocket with Callback

```python
import asyncio
from cipherrun import WebSocketProgressClient, ProgressMessage

async def handle_progress(progress: ProgressMessage):
    print(f"[{progress.timestamp}] {progress.stage}: {progress.progress}%")
    if progress.details:
        print(f"  Details: {progress.details}")

async def main():
    async with WebSocketProgressClient() as ws_client:
        await ws_client.stream_progress_with_callback(
            scan_id="your-scan-id",
            callback=handle_progress,
        )

asyncio.run(main())
```

## Models

All request and response data is validated using Pydantic v2 models:

```python
from cipherrun import (
    ScanResults,
    ProtocolTestResult,
    VulnerabilityResult,
    CertificateAnalysisResult,
    HeaderAnalysisResult,
    RatingResult,
)

results: ScanResults = client.get_scan_results(scan_id)

# Access typed data
for protocol in results.protocols:
    print(f"{protocol.protocol}: {'Supported' if protocol.supported else 'Not supported'}")

for vuln in results.vulnerabilities:
    if vuln.vulnerable:
        print(f"[{vuln.severity}] {vuln.vuln_type}: {vuln.details}")

if results.rating:
    print(f"Overall Grade: {results.rating.grade}")
    print(f"Score: {results.rating.score}/100")
```

## Development

### Install Development Dependencies

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

### Type Checking

```bash
mypy cipherrun
```

### Code Formatting

```bash
black cipherrun
ruff check cipherrun
```

## Requirements

- Python 3.8+
- requests >= 2.31.0
- aiohttp >= 3.9.0
- websockets >= 12.0
- pydantic >= 2.0.0

## License

MIT License - see LICENSE file for details

## Support

- Documentation: https://docs.cipherrun.com
- Issues: https://github.com/yourusername/cipherrun/issues
- Email: support@cipherrun.com

## Examples

See the `examples/` directory for more usage examples:
- `basic_scan.py` - Basic synchronous scanning
- `async_scan.py` - Async batch scanning
- `websocket_progress.py` - Real-time progress monitoring
- `compliance_check.py` - Compliance checking
- `policy_evaluation.py` - Policy-based evaluation
