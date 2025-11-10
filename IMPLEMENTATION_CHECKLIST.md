# CipherRun - tlsx Parity Implementation Checklist

## 🎯 Goal: Achieve 100% Feature Parity with tlsx

**Current Progress:** 32/47 features (68.1%)
**Remaining:** 15 features
**Estimated Time:** 14-18 weeks

---

## 📋 CRITICAL PRIORITY (Weeks 1-8)

### ❌ 1. Certificate Transparency (CT) Logs Streaming
**Complexity:** 2-3 weeks | **Priority:** ⭐⭐⭐⭐⭐

**Implementation Tasks:**
- [ ] Research CT log ecosystem and APIs
  - [ ] Google CT logs
  - [ ] Cloudflare Nimbus
  - [ ] DigiCert
  - [ ] Let's Encrypt
- [ ] Integrate CT log client library
  - [ ] Evaluate: `ct-go`, `certificate-transparency-go`
  - [ ] Choose async/streaming library
- [ ] Implement streaming mode
  - [ ] Fire-hose mode (continuous streaming)
  - [ ] Start from current tree size (default)
  - [ ] Start from index 0 (--ctl-beginning)
  - [ ] Custom start indices (--ctl-index)
- [ ] Add duplicate detection
  - [ ] Implement inverse bloom filter
  - [ ] Configurable filter size
- [ ] Certificate parsing and conversion
  - [ ] X.509 parsing from raw DER
  - [ ] Convert to CipherRun Response format
- [ ] CLI flags
  - [ ] `--ct-logs` / `-ctl`
  - [ ] `--ctl-beginning` / `-cb`
  - [ ] `--ctl-index` / `-cti`
- [ ] Output integration
  - [ ] JSON output support
  - [ ] SAN extraction (default)
  - [ ] Certificate inclusion (--cert flag)
- [ ] Testing
  - [ ] Test with major CT logs
  - [ ] Verify duplicate filtering
  - [ ] Performance benchmarking
  - [ ] Long-running stability test

**Dependencies:**
- Certificate parsing library (already have: x509-parser)
- Async runtime (already have: tokio)
- HTTP client (already have: reqwest)

**Deliverables:**
- CT logs streaming module (`src/ctlogs/`)
- CLI integration
- Documentation
- Examples

---

### ❌ 2. JA3 TLS Client Fingerprinting
**Complexity:** 1-2 weeks | **Priority:** ⭐⭐⭐⭐⭐

**Implementation Tasks:**
- [ ] Study JA3 specification
  - [ ] Understand JA3 hash algorithm
  - [ ] Review Salesforce reference implementation
- [ ] Extract Client Hello fields
  - [ ] TLS version
  - [ ] Cipher suites list
  - [ ] Extensions list
  - [ ] Elliptic curves
  - [ ] Elliptic curve point formats
- [ ] Implement JA3 hash generation
  - [ ] Concatenate fields with commas
  - [ ] MD5 hash of concatenated string
- [ ] Low-level packet capture
  - [ ] Access raw Client Hello bytes
  - [ ] Parse TLS handshake records
  - [ ] Extract fields without full handshake
- [ ] CLI flag
  - [ ] `--ja3`
- [ ] Output integration
  - [ ] Add `ja3_hash` field to JSON output
  - [ ] Terminal display option
- [ ] Testing
  - [ ] Verify against known JA3 hashes
  - [ ] Test with multiple browsers/clients
  - [ ] Validate hash consistency

**Dependencies:**
- Low-level TLS library for packet inspection
- Consider: custom ztls-like implementation or use existing Rust TLS libraries

**Deliverables:**
- JA3 module (`src/fingerprint/ja3.rs`)
- Client Hello parser
- Integration with scanner
- Test suite with known hashes

---

### ❌ 3. JA3S TLS Server Fingerprinting
**Complexity:** 1-2 weeks | **Priority:** ⭐⭐⭐⭐⭐

**Implementation Tasks:**
- [ ] Study JA3S specification
  - [ ] Server-side JA3 algorithm
  - [ ] Differences from JA3
- [ ] Extract Server Hello fields
  - [ ] TLS version
  - [ ] Cipher suite (single)
  - [ ] Extensions list
- [ ] Implement JA3S hash generation
  - [ ] Concatenate server fields
  - [ ] MD5 hash generation
- [ ] Low-level packet capture
  - [ ] Access raw Server Hello bytes
  - [ ] Parse server handshake records
- [ ] CLI flag
  - [ ] `--ja3s`
- [ ] Output integration
  - [ ] Add `ja3s_hash` field to JSON
  - [ ] Terminal display
- [ ] Testing
  - [ ] Verify against known JA3S hashes
  - [ ] Test with various servers
  - [ ] Validate consistency

**Dependencies:**
- JA3 implementation (can share code)
- Server Hello parser

**Deliverables:**
- JA3S module (`src/fingerprint/ja3s.rs`)
- Server Hello parser
- Integration with scanner
- Test suite

---

## 🔴 HIGH PRIORITY (Weeks 9-14)

### ❌ 4. Pre-Handshake / Early Termination
**Complexity:** 1 week | **Priority:** ⭐⭐⭐⭐

**Implementation Tasks:**
- [ ] Study TLS handshake state machine
  - [ ] Identify termination point (after ServerHello + Certificate)
  - [ ] Ensure graceful connection closure
- [ ] Implement early termination
  - [ ] Modify TLS client to disconnect early
  - [ ] Capture necessary data before disconnect
- [ ] Create custom TLS state machine
  - [ ] ClientHello → ServerHello → Certificate → DISCONNECT
  - [ ] Skip ChangeCipherSpec, Finished messages
- [ ] CLI flag
  - [ ] `--pre-handshake` / `-ps`
- [ ] Performance optimization
  - [ ] Measure speed improvement
  - [ ] Reduce server load
- [ ] Testing
  - [ ] Verify data collection completeness
  - [ ] Test with various TLS versions
  - [ ] Compare speed vs full handshake

**Dependencies:**
- Low-level TLS control
- Consider: custom TLS implementation or fork existing library

**Deliverables:**
- Pre-handshake module (`src/protocols/pre_handshake.rs`)
- Modified TLS client
- Performance benchmarks

---

### ❌ 5. Scan All IPs for Hostname
**Complexity:** 3-5 days | **Priority:** ⭐⭐⭐⭐

**Implementation Tasks:**
- [ ] Enhance DNS resolution
  - [ ] Query all A records
  - [ ] Query all AAAA records (IPv6)
  - [ ] Deduplicate IP addresses
- [ ] Multi-IP scanning logic
  - [ ] Scan each IP separately
  - [ ] Aggregate results
  - [ ] Report minimum capability across all IPs
- [ ] Result aggregation
  - [ ] Determine "weakest link" logic
  - [ ] Combine certificate chains
  - [ ] Merge vulnerability results
- [ ] CLI flag
  - [ ] `--scan-all-ips` / `-sa`
- [ ] Output formatting
  - [ ] Show results per IP
  - [ ] Show aggregate results
- [ ] Testing
  - [ ] Test with multi-IP hosts (CDNs, Anycast)
  - [ ] Verify aggregation logic
  - [ ] Test with IPv4 and IPv6

**Dependencies:**
- DNS resolver (already have: hickory-resolver)
- Aggregation logic

**Deliverables:**
- Multi-IP scanner (`src/scanner/multi_ip.rs`)
- Result aggregation module
- Test cases

---

### ❌ 6. Random SNI Generation
**Complexity:** 2-3 days | **Priority:** ⭐⭐⭐

**Implementation Tasks:**
- [ ] Implement random hostname generator
  - [ ] Generate realistic domain names
  - [ ] Use random dictionary words + TLDs
  - [ ] Configurable length/format
- [ ] CLI flag
  - [ ] `--random-sni` / `-rs`
- [ ] Integration
  - [ ] Use when no SNI provided
  - [ ] Override detection logic
- [ ] Testing
  - [ ] Verify randomness
  - [ ] Test server responses
  - [ ] Ensure uniqueness per connection

**Dependencies:**
- Random generator (already have: rand)

**Deliverables:**
- Random SNI module (`src/utils/random_sni.rs`)
- Integration with TLS client
- Tests

---

### ❌ 7. Reverse PTR SNI
**Complexity:** 3-5 days | **Priority:** ⭐⭐⭐

**Implementation Tasks:**
- [ ] Implement reverse DNS lookup
  - [ ] PTR record query
  - [ ] Handle multiple PTR records
  - [ ] Error handling for missing PTR
- [ ] CLI flag
  - [ ] `--rev-ptr-sni` / `-rps`
- [ ] Integration logic
  - [ ] Perform PTR lookup before TLS connection
  - [ ] Use PTR result as SNI
  - [ ] Fallback to IP if no PTR
- [ ] Testing
  - [ ] Test with various IPs
  - [ ] Test with no PTR records
  - [ ] Test with multiple PTR records

**Dependencies:**
- DNS resolver (already have: hickory-resolver)

**Deliverables:**
- PTR lookup module (`src/utils/ptr_sni.rs`)
- Integration with scanner
- Tests

---

### ❌ 8. ASN and CIDR Input Support
**Complexity:** 1 week | **Priority:** ⭐⭐⭐⭐

**Implementation Tasks:**
- [ ] ASN to IP range mapping
  - [ ] Integrate ASN database (e.g., MaxMind, Team Cymru)
  - [ ] Query ASN → CIDR mappings
  - [ ] Handle large ASNs
- [ ] CIDR expansion
  - [ ] Parse CIDR notation
  - [ ] Expand to individual IPs
  - [ ] Support IPv4 and IPv6 CIDRs
- [ ] Input parsing enhancement
  - [ ] Detect ASN format (AS1449)
  - [ ] Detect CIDR format (173.0.84.0/24)
  - [ ] Expand before scanning
- [ ] CLI support
  - [ ] Accept ASN/CIDR in input
  - [ ] Show expansion statistics
- [ ] Testing
  - [ ] Test with various ASNs
  - [ ] Test with various CIDR ranges
  - [ ] Test with large expansions

**Dependencies:**
- ASN database/API
- CIDR library (consider: ipnet crate)

**Deliverables:**
- ASN mapper (`src/utils/asn.rs`)
- CIDR expander (`src/utils/cidr.rs`)
- Input parser enhancement
- Tests

---

### ❌ 9. Client/Server Hello Raw Data Export
**Complexity:** 1-2 weeks | **Priority:** ⭐⭐⭐

**Implementation Tasks:**
- [ ] Capture Client Hello raw bytes
  - [ ] Hook into TLS library
  - [ ] Extract complete handshake message
  - [ ] Hex encode for output
- [ ] Capture Server Hello raw bytes
  - [ ] Extract server handshake message
  - [ ] Include extensions
  - [ ] Hex encode for output
- [ ] CLI flags
  - [ ] `--client-hello` / `-ch`
  - [ ] `--server-hello` / `-sh`
- [ ] Output integration
  - [ ] Add to JSON output
  - [ ] Base64 or hex encoding
  - [ ] Optional terminal display
- [ ] Testing
  - [ ] Verify data completeness
  - [ ] Test encoding/decoding
  - [ ] Validate with Wireshark captures

**Dependencies:**
- Low-level TLS packet access
- Base64/hex encoding (already have: base64, hex crates)

**Deliverables:**
- Handshake capture module (`src/protocols/handshake_capture.rs`)
- JSON output integration
- Tests with known captures

---

### ❌ 10. TLS Probe Status
**Complexity:** 2-3 days | **Priority:** ⭐⭐⭐

**Implementation Tasks:**
- [ ] Enhance connection result handling
  - [ ] Return explicit success/failure status
  - [ ] Include error details
- [ ] CLI flag
  - [ ] `--probe-status` / `-tps`
- [ ] Output integration
  - [ ] Add `probe_status` boolean to JSON
  - [ ] Add error message field
  - [ ] Terminal display format
- [ ] Return response on failure
  - [ ] Create partial response object
  - [ ] Include host, port, SNI
  - [ ] Include error details
- [ ] Testing
  - [ ] Test with successful connections
  - [ ] Test with connection failures
  - [ ] Test with timeout scenarios

**Dependencies:**
- Enhanced error handling
- Result type modification

**Deliverables:**
- Probe status module
- Output format updates
- Tests

---

## 🟡 MEDIUM PRIORITY (Weeks 15-17)

### ❌ 11. DNS-Only Output Mode
**Complexity:** 2-3 days | **Priority:** ⭐⭐

**Implementation Tasks:**
- [ ] Extract DNS names from certificates
  - [ ] Parse SAN extension
  - [ ] Parse CN field
  - [ ] Combine and deduplicate
- [ ] CLI flag
  - [ ] `--dns`
- [ ] Output mode
  - [ ] Output only DNS names
  - [ ] One per line
  - [ ] Deduplicated
- [ ] Testing
  - [ ] Test with various certificates
  - [ ] Test deduplication
  - [ ] Test with wildcard certs

**Deliverables:**
- DNS extraction module
- Output formatter
- Tests

---

### ❌ 12. Response-Only Output Mode
**Complexity:** 2-3 days | **Priority:** ⭐⭐

**Implementation Tasks:**
- [ ] Implement minimal output mode
  - [ ] Output only response data
  - [ ] No metadata, no banners
  - [ ] No statistics
- [ ] CLI flag
  - [ ] `--resp-only` / `-ro`
- [ ] Output formatter
  - [ ] Minimal JSON
  - [ ] Or just the requested fields
- [ ] Testing
  - [ ] Verify minimal output
  - [ ] Test with various probes

**Deliverables:**
- Minimal output formatter
- Tests

---

### ❌ 13. Custom Resolvers Support
**Complexity:** 3-5 days | **Priority:** ⭐⭐

**Implementation Tasks:**
- [ ] DNS resolver configuration
  - [ ] Accept custom DNS servers
  - [ ] Support DoH (DNS over HTTPS)
  - [ ] Support DoT (DNS over TLS)
- [ ] CLI flag
  - [ ] `--resolvers` / `-r`
  - [ ] Accept comma-separated list
  - [ ] Accept file input
- [ ] Integration
  - [ ] Configure hickory-resolver
  - [ ] Override system defaults
- [ ] Testing
  - [ ] Test with public resolvers (8.8.8.8, 1.1.1.1)
  - [ ] Test with DoH servers
  - [ ] Test resolution accuracy

**Dependencies:**
- DNS resolver library (already have: hickory-resolver)

**Deliverables:**
- Custom resolver configuration
- CLI integration
- Tests

---

### ❌ 14. Connection Delay / Rate Limiting
**Complexity:** 2-3 days | **Priority:** ⭐⭐

**Implementation Tasks:**
- [ ] Implement per-thread delay
  - [ ] Parse duration string (200ms, 1s, etc.)
  - [ ] Apply delay between connections
  - [ ] Per-worker thread, not global
- [ ] CLI flag
  - [ ] `--delay <DURATION>`
- [ ] Integration
  - [ ] Add to worker loop
  - [ ] Don't delay initial connection
- [ ] Testing
  - [ ] Verify timing accuracy
  - [ ] Test with various delays
  - [ ] Measure rate limiting effectiveness

**Note:** Different from existing `--sleep` flag

**Dependencies:**
- Duration parsing
- Timer (already have: tokio time)

**Deliverables:**
- Delay implementation in scanner
- Tests

---

### ❌ 15. Hard Fail on Revocation Check Errors
**Complexity:** 2-3 days | **Priority:** ⭐⭐

**Implementation Tasks:**
- [ ] Enhance revocation checking
  - [ ] Track CRL/OCSP check failures
  - [ ] Distinguish between "revoked" and "check failed"
- [ ] CLI flag
  - [ ] `--hardfail` / `-hf`
- [ ] Implementation
  - [ ] Treat check failures as revoked
  - [ ] Fail certificate validation on error
- [ ] Output
  - [ ] Report hard-fail status
  - [ ] Include error details
- [ ] Testing
  - [ ] Test with failing OCSP responders
  - [ ] Test with unreachable CRL servers
  - [ ] Test with valid responses

**Dependencies:**
- Existing revocation checking (already implemented)

**Deliverables:**
- Hard-fail mode in certificate validator
- Tests

---

## 📊 Progress Tracking

### Overall Progress
- [ ] Critical Features: 0/3 (0%)
- [ ] High Features: 0/7 (0%)
- [ ] Medium Features: 0/5 (0%)
- [ ] **Total: 0/15 (0%)**

### Phase Completion
- [ ] Phase 1: Critical (Weeks 1-8)
- [ ] Phase 2: High (Weeks 9-14)
- [ ] Phase 3: Medium (Weeks 15-17)
- [ ] Phase 4: Testing & Docs (Weeks 18-20)

---

## 🧪 Testing Strategy

### Unit Tests
- [ ] CT logs streaming
- [ ] JA3/JA3S hash generation
- [ ] ASN/CIDR expansion
- [ ] DNS extraction
- [ ] All new modules

### Integration Tests
- [ ] End-to-end scanning with new features
- [ ] Feature combination testing
- [ ] Backwards compatibility

### Performance Tests
- [ ] CT logs streaming performance
- [ ] Pre-handshake speed improvement
- [ ] Multi-IP scanning overhead
- [ ] Overall scan throughput

### Compatibility Tests
- [ ] Test against tlsx for parity
- [ ] Verify output format compatibility
- [ ] CLI flag compatibility

---

## 📚 Documentation Tasks

- [ ] Update README.md with new features
- [ ] Add examples for each new feature
- [ ] Create migration guide from tlsx
- [ ] Update CLI help text
- [ ] Add to --help output
- [ ] Create comparison table with tlsx
- [ ] Write blog post about parity achievement
- [ ] Update website documentation

---

## 🎉 Definition of Done

**Feature Parity Achieved When:**
- ✅ All 15 missing features implemented
- ✅ All tests passing (unit + integration)
- ✅ Documentation complete
- ✅ Performance benchmarks meet or exceed tlsx
- ✅ Code review completed
- ✅ Examples created and tested
- ✅ Backwards compatibility maintained
- ✅ Release notes prepared

**Success Criteria:**
- 100% feature parity with tlsx (47/47 features)
- Maintains all 36 unique CipherRun features
- Performance within 10% of tlsx for equivalent operations
- Zero regression in existing features

---

**Created:** 2025-11-10
**Target Completion:** Q2 2025
**Owner:** Development Team
