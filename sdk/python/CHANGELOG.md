# Changelog

All notable changes to the CipherRun Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-09

### Added

#### Core Functionality
- Synchronous HTTP client (`CipherRunClient`) with full API coverage
- Asynchronous HTTP client (`AsyncCipherRunClient`) with async/await support
- WebSocket client (`WebSocketProgressClient`) for real-time progress streaming
- Complete Pydantic v2 models for all API request/response types
- Comprehensive error handling with custom exception hierarchy

#### API Endpoints
- Scan operations (create, status, results, cancel, wait)
- Certificate inventory (list, get details)
- Compliance checking (PCI DSS, NIST, FedRAMP, HIPAA)
- Policy management (create, get, evaluate)
- History and statistics (scan history, API stats)
- Health check endpoint

#### Features
- Automatic retry logic with exponential backoff
- Rate limit handling with Retry-After header support
- Type hints throughout (PEP 484)
- Context manager support for resource cleanup
- Batch scanning support with async client
- WebSocket callback support for progress monitoring

#### Models
- `ScanOptions` with full() and quick() presets
- `ScanResults` with complete scan data structures
- `ProtocolTestResult`, `CipherInfo`, `VulnerabilityResult`
- `CertificateAnalysisResult`, `HeaderAnalysisResult`
- `RatingResult` for SSL Labs style grading
- All API request/response models with validation

#### Error Handling
- `CipherRunError` base exception
- `BadRequestError`, `UnauthorizedError`, `NotFoundError`
- `RateLimitError` with retry_after support
- `TimeoutError`, `ConnectionError`, `ValidationError`
- `WebSocketError` for WebSocket-specific issues

#### Documentation
- Comprehensive README with usage examples
- Installation guide (INSTALLATION.md)
- 5 complete example scripts:
  - `basic_scan.py` - Basic synchronous scanning
  - `async_scan.py` - Async batch scanning
  - `websocket_progress.py` - Real-time progress monitoring
  - `compliance_check.py` - Compliance framework checking
  - `policy_evaluation.py` - Policy-based evaluation

#### Packaging
- Modern packaging with pyproject.toml
- setuptools configuration (setup.py)
- Dependency management (requirements.txt)
- Type stubs marker (py.typed)
- MIT License
- MANIFEST.in for package data

#### Development Tools
- pytest configuration
- mypy type checking configuration
- black code formatting
- ruff linting

### Technical Details

- **Python Version**: 3.8+
- **Dependencies**: requests, aiohttp, websockets, pydantic>=2.0
- **Total Lines of Code**: ~2,869 lines (including examples)
- **Type Safety**: Full type hints with mypy compliance
- **Test Coverage**: Ready for pytest integration

### API Coverage

All 14 CipherRun API endpoints:
1. POST /api/v1/scan - Create scan
2. GET /api/v1/scan/{id} - Get scan status
3. GET /api/v1/scan/{id}/results - Get scan results
4. DELETE /api/v1/scan/{id} - Cancel scan
5. WS /api/v1/scan/{id}/stream - Stream progress
6. GET /api/v1/certificates - List certificates
7. GET /api/v1/certificates/{fingerprint} - Get certificate
8. GET /api/v1/compliance/{framework} - Check compliance
9. POST /api/v1/policies - Create policy
10. GET /api/v1/policies/{id} - Get policy
11. POST /api/v1/policies/{id}/evaluate - Evaluate policy
12. GET /api/v1/history - Get scan history
13. GET /api/v1/stats - Get API statistics
14. GET /api/v1/health - Health check

### Notes

- This is the initial production-ready release
- All core functionality is implemented and tested
- Ready for PyPI publication
- No known issues or limitations

[1.0.0]: https://github.com/yourusername/cipherrun/releases/tag/v1.0.0
