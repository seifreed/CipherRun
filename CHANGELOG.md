# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2025-01-12

### Added
- New CLI flag `--max-concurrent-ciphers` to control concurrency during cipher suite testing
  - Default value: 10
  - Allows users to reduce concurrent connections to avoid network saturation
  - Example: `cipherrun example.com --max-concurrent-ciphers 5`

### Fixed
- **Critical**: Fixed ENETDOWN (error 50) "Network is down" errors during cipher testing
  - Implemented retry logic specifically for ENETDOWN errors
  - Added adaptive backoff mechanism that automatically reduces concurrency when network saturation is detected
  - Implemented intelligent retry queue for ciphers that fail with ENETDOWN
  - Retries up to 3 times with exponential backoff (5-8 seconds depending on error severity)
  - Scans now complete successfully instead of crashing when network stack becomes saturated
  - Particularly improves reliability on macOS and systems with conservative network limits

### Changed
- Enhanced retry system to recognize ENETDOWN as a retriable transient error
- Improved cipher testing algorithm with batch processing and adaptive concurrency adjustment
- More aggressive concurrency reduction when >50% of tests fail (divides by 3 instead of 2)
- Extended recovery delays between batches (5-8 seconds) to allow network stack to stabilize
- Better error logging and diagnostic messages during cipher testing

### Technical Details
- Modified `src/utils/retry.rs` to detect and retry ENETDOWN errors
- Updated `src/ciphers/tester.rs` with adaptive backoff and retry queue
- Enhanced `src/scanner/mod.rs` to pass retry configuration to cipher tester
- Added comprehensive test coverage for ENETDOWN error handling

### Performance
- Minimal impact on scan time for stable networks
- Slightly longer scan time for networks experiencing saturation (but now completes instead of failing)
- Recommended settings for unstable networks: `--max-concurrent-ciphers 2 --sleep 300`

## [0.2.0] - Previous Release

Initial release with core TLS/SSL scanning functionality.

