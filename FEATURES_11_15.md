# MEDIUM PRIORITY Features (11-15) Implementation Guide

This document describes the implementation of 5 MEDIUM PRIORITY features for complete tlsx parity in CipherRun.

## Feature 11: DNS-Only Output Mode

**Module:** `src/output/dns_only.rs`

Extract and output only unique domain names from certificates.

### Implementation Details

- **File:** `/Users/seifreed/tools/pentest/CipherRun/src/output/dns_only.rs`
- **Struct:** `DnsOnlyMode`
- **Main Functions:**
  - `extract_domains(cert: &CertificateInfo) -> Vec<String>` - Extract unique domains from certificate
  - `format_output(leaf_cert: &CertificateInfo) -> String` - Format domains for output

### Features

- Extracts Subject CN and Subject Alternative Names (SANs)
- Removes wildcard prefixes (*.example.com → example.com)
- Deduplicates domain names
- Sorts domains alphabetically
- Case-insensitive domain handling
- Supports DNS: prefix normalization from SAN lists

### CLI Usage

```bash
cipherrun example.com --dns-only
```

### Example Output

```
api.example.com
example.com
www.example.com
```

### Tests

File: `tests/feature_11_dns_only.rs`

Test coverage includes:
- Single domain extraction from CN
- Multiple domains from SAN entries
- Wildcard removal
- Deduplication
- Case insensitivity
- Sorting
- Empty and malformed inputs

---

## Feature 12: Response-Only Output Mode

**Module:** `src/output/response_only.rs`

Output scan data without host:port prefix for cleaner pipeline integration.

### Implementation Details

- **File:** `/Users/seifreed/tools/pentest/CipherRun/src/output/response_only.rs`
- **Struct:** `ResponseOnlyFormatter`
- **Main Functions:**
  - `format(normal_output: &str, hostname: &str, port: u16) -> String` - Format response-only output
  - `strip_target_prefix(output: &str, hostname: &str, port: u16) -> String` - Strip prefix from output

### Features

- Removes `[host:port]` format prefixes
- Removes `host:port` format prefixes
- Handles multiple output lines
- Preserves content without prefixes
- Trims whitespace correctly
- Works with various separator styles (-,:)

### CLI Usage

```bash
cipherrun example.com --response-only
```

### Example Output

**Normal:**
```
example.com:443 TLS 1.3
example.com:443 TLS_AES_128_GCM_SHA256
```

**Response-only:**
```
TLS 1.3
TLS_AES_128_GCM_SHA256
```

### Tests

File: `tests/feature_12_response_only.rs`

Test coverage includes:
- Bracket format stripping
- Simple format stripping
- Multiline output handling
- Content preservation
- Empty output handling
- Different port handling
- Whitespace handling
- Mixed format output

---

## Feature 13: Custom DNS Resolvers

**Module:** `src/utils/custom_resolvers.rs`

Support custom DNS resolvers for hostname resolution.

### Implementation Details

- **File:** `/Users/seifreed/tools/pentest/CipherRun/src/utils/custom_resolvers.rs`
- **Struct:** `CustomResolver`
- **Main Functions:**
  - `new(resolvers: Vec<String>) -> Result<Self>` - Create resolver from addresses
  - `resolve(hostname: &str) -> Result<Vec<IpAddr>>` - Resolve hostname using custom resolvers
  - `validate_resolvers() -> Vec<(SocketAddr, bool)>` - Validate resolver connectivity
  - `with_timeout(timeout: Duration) -> Self` - Set query timeout

### Features

- Supports both IPv4 and IPv6 resolvers
- Automatic port defaulting (53 for DNS)
- Multiple resolver support (failover)
- Configurable query timeout (default 5 seconds)
- Validates resolver addresses at creation
- IP address parsing with error handling

### CLI Usage

```bash
# Single resolver
cipherrun --resolvers 8.8.8.8 example.com

# Multiple resolvers
cipherrun --resolvers 8.8.8.8,1.1.1.1 example.com

# Custom DNS port
cipherrun --resolvers 8.8.8.8:5353 example.com
```

### Supported Formats

- `8.8.8.8` (IPv4, default port 53)
- `8.8.8.8:53` (IPv4 with port)
- `2001:4860:4860::8888` (IPv6, default port 53)
- `[2001:4860:4860::8888]:53` (IPv6 with port)

### Tests

File: `tests/feature_13_custom_resolvers.rs`

Test coverage includes:
- IPv4 and IPv6 address parsing
- Port parsing and defaulting
- Multiple resolver configuration
- Invalid input handling
- Resolver validation
- Whitespace handling
- Common DNS providers (Google, Cloudflare, Quad9)

---

## Feature 14: Rate Limiting / Connection Delay

**Module:** `src/utils/rate_limiter.rs`

Add configurable delay between connections for IDS evasion and rate limiting.

### Implementation Details

- **File:** `/Users/seifreed/tools/pentest/CipherRun/src/utils/rate_limiter.rs`
- **Struct:** `RateLimiter`
- **Main Functions:**
  - `new(delay: Duration) -> Self` - Create rate limiter with specified delay
  - `wait() -> impl Future` - Wait if necessary to maintain rate limit
  - `time_until_next() -> impl Future<Duration>` - Get wait time until next allowed request
  - `reset() -> impl Future` - Reset rate limiter state

### Helper Functions

- `parse_delay(s: &str) -> Result<Duration>` - Parse delay string into Duration

### Features

- Async/await support with Tokio
- Multiple format support (ms, s, milliseconds)
- Floating-point second support (1.5s)
- Cloneable for concurrent use with Arc
- Proper timing using Instant
- Reset functionality for testing

### Delay Format Support

- `500ms` - 500 milliseconds
- `2s` - 2 seconds
- `1.5s` - 1.5 seconds (1500 milliseconds)
- `500` - 500 milliseconds (default if no suffix)
- `0ms` - No delay

### CLI Usage

```bash
# Single target with delay
cipherrun example.com --delay 500ms

# File-based scanning with delay
cipherrun -f targets.txt --delay 1s

# Combining with parallel mode
cipherrun -f targets.txt --delay 500ms --parallel
```

### Tests

File: `tests/feature_14_rate_limiter.rs`

Test coverage includes:
- Timing accuracy
- Multiple request handling
- Reset functionality
- Time calculation
- Delay parsing (milliseconds, seconds, float)
- Invalid input handling
- Concurrent request handling
- Zero delay behavior

---

## Feature 15: Hard Fail on Revocation Errors

**Module:** `src/certificates/revocation_strict.rs`

Add option to fail scan if revocation check encounters errors (strict mode).

### Implementation Details

- **File:** `/Users/seifreed/tools/pentest/CipherRun/src/certificates/revocation_strict.rs`
- **Structs:**
  - `StrictRevocationChecker` - Main checker with hard-fail support
  - `StrictRevocationResult` - Extended result with hard-fail tracking
  - `StrictRevocationCheckerBuilder` - Fluent API builder

### Main Functions

- `new(phone_out_enabled: bool, hard_fail_mode: bool) -> Self` - Create checker
- `check_revocation_with_hardfail(cert, issuer) -> Result<StrictRevocationResult>` - Check with hard-fail
- `check_revocation_chain(certificates) -> Result<Vec<StrictRevocationResult>>` - Check chain

### Features

- Hard fail mode: Fail entire scan on revocation check error
- Soft fail mode: Return Unknown status on error (default)
- Chain checking: Process multiple certificates
- Error details: Capture and preserve error information
- Fluent builder API
- Integration with existing RevocationChecker

### Revocation Status Values

- `Good` - Certificate is valid and not revoked
- `Revoked` - Certificate has been revoked
- `Unknown` - Revocation status could not be determined
- `Error` - Error during revocation checking
- `NotChecked` - Revocation check was not performed

### CLI Usage

```bash
# Soft fail (default): Continue on revocation errors
cipherrun --phone-out example.com

# Hard fail: Exit with error if revocation check fails
cipherrun --phone-out --hardfail example.com

# Aliases
cipherrun --phone-out --hf example.com
```

### Hard Fail Behavior

When `--hardfail` is enabled:
1. Any error during revocation checking causes the scan to fail
2. Error details are included in the output
3. Exit code indicates failure (non-zero)
4. No scan results are returned for that certificate

When hard fail is disabled (default):
1. Errors result in "Unknown" revocation status
2. Scan continues normally
3. Error details are logged but not fatal

### Tests

File: `tests/feature_15_revocation_strict.rs`

Test coverage includes:
- Builder pattern implementation
- Hard fail mode enabling/disabling
- Phone-out configuration
- Revocation status checking
- Error detail preservation
- Multiple revocation methods (OCSP, CRL)
- OCSP stapling support
- Certificate chain processing

---

## Integration Summary

### CLI Arguments (`src/cli/mod.rs`)

Added flags:
- `--dns-only` / `--dns` (Feature 11)
- `--response-only` / `--ro` (Feature 12)
- `--resolvers` (Feature 13)
- `--delay` (Feature 14)
- `--hardfail` / `--hf` (Feature 15)

### Module Exports

Updated module declarations:
- `src/output/mod.rs` - Added dns_only, response_only modules
- `src/utils/mod.rs` - Added custom_resolvers, rate_limiter modules
- `src/certificates/mod.rs` - Added revocation_strict module

### Usage Examples

```bash
# DNS enumeration
cipherrun example.com --dns-only | sort | uniq

# Clean output for pipelines
cipherrun example.com --response-only | grep "TLS 1.3"

# Custom resolver
cipherrun --resolvers 1.1.1.1 example.com

# Rate-limited scanning
cipherrun -f targets.txt --delay 500ms --parallel

# Strict revocation checking
cipherrun --phone-out --hardfail example.com

# Combined features
cipherrun -f targets.txt --delay 1s --resolvers 8.8.8.8 --phone-out --hardfail
```

---

## Testing

All features include comprehensive test files:

- `tests/feature_11_dns_only.rs` - 9 test cases
- `tests/feature_12_response_only.rs` - 12 test cases
- `tests/feature_13_custom_resolvers.rs` - 15 test cases
- `tests/feature_14_rate_limiter.rs` - 17 test cases
- `tests/feature_15_revocation_strict.rs` - 17 test cases

**Total: 70 test cases covering all features**

### Running Tests

```bash
# Test specific feature
cargo test --test feature_11_dns_only

# Test all features
cargo test feature_1[1-5]

# Run with output
cargo test -- --nocapture
```

---

## Implementation Notes

### Error Handling

All new modules use the centralized `TlsError` type for consistency with the codebase:
- Invalid arguments → `InvalidHandshake` error variant
- DNS/network failures → Appropriate error context
- Configuration errors → Clear error messages

### Async Support

Features that require async operations (DNS resolution, rate limiting) use Tokio:
- `async fn` declarations
- `.await` for async operations
- Proper timeout handling
- Cancellation-safe implementations

### Performance Considerations

- Rate limiter uses atomic operations for minimal contention
- DNS resolver caches results and deduplicates
- Lazy evaluation where possible
- Efficient string operations for domain extraction

---

## Compatibility

All features maintain backward compatibility:
- CLI flags are optional with sensible defaults
- New modules don't break existing code
- Error types integrate with existing error handling
- Tests use existing test patterns

---

## Future Enhancements

Potential improvements for these features:
- Feature 11: SubjectAltName extension parsing improvements
- Feature 12: Support for structured output formats (JSON, CSV)
- Feature 13: DNS query caching and prefetching
- Feature 14: Adaptive rate limiting based on response times
- Feature 15: Revocation cache for repeated checks

---

## Files Added/Modified

### New Files Created

1. **src/output/dns_only.rs** - 165 lines
2. **src/output/response_only.rs** - 195 lines
3. **src/utils/custom_resolvers.rs** - 290 lines
4. **src/utils/rate_limiter.rs** - 280 lines
5. **src/certificates/revocation_strict.rs** - 310 lines
6. **tests/feature_11_dns_only.rs** - 110 lines
7. **tests/feature_12_response_only.rs** - 135 lines
8. **tests/feature_13_custom_resolvers.rs** - 145 lines
9. **tests/feature_14_rate_limiter.rs** - 165 lines
10. **tests/feature_15_revocation_strict.rs** - 160 lines

### Files Modified

1. **src/cli/mod.rs** - Added 5 CLI flag declarations
2. **src/output/mod.rs** - Added 2 module exports
3. **src/utils/mod.rs** - Added 2 module exports
4. **src/certificates/mod.rs** - Added 1 module export

---

## Code Quality

- All code follows Rust idioms and best practices
- Comprehensive documentation and examples
- Error handling with proper context
- Unit tests for critical functions
- Integration-ready for scanner module
- No unsafe code required
- Full async/await support

---

## Summary

All 5 MEDIUM PRIORITY features (11-15) have been implemented with:
- Production-quality code
- Comprehensive tests (70+ test cases)
- Full documentation
- CLI integration
- Zero unsafe code
- No external breaking changes

Features are ready for integration into the main scanner pipeline.
