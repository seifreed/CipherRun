# JA3S TLS Server Fingerprinting

## Overview

JA3S is a method for creating SSL/TLS server fingerprints based on the ServerHello message. It was developed by Salesforce as a companion to JA3 (client fingerprinting) to identify and track TLS servers, CDNs, load balancers, and server software.

## Algorithm

### JA3S String Format

```
SSLVersion,Cipher,Extensions
```

- **SSLVersion**: Decimal representation of TLS version (e.g., 771 for TLS 1.2)
- **Cipher**: Single selected cipher suite in decimal format
- **Extensions**: Comma-separated extension IDs in decimal, preserving order

### JA3S Hash

The JA3S string is hashed using MD5 to produce a 32-character hexadecimal fingerprint.

### Example

```
ServerHello Components:
  SSL Version: TLS 1.2 (0x0303 = 771)
  Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F = 49199)
  Extensions: renegotiation_info (65281), server_name (0), ec_point_formats (11),
              session_ticket (35), extended_master_secret (23)

JA3S String: 771,49199,65281-0-11-35-23
JA3S Hash:   623de93db17d313345d7ea481e7443cf
```

## Key Differences from JA3

| Feature | JA3 (Client) | JA3S (Server) |
|---------|--------------|---------------|
| Message | ClientHello | ServerHello |
| Cipher Suites | Multiple offered | Single selected |
| Extensions | Client extensions | Server extensions |
| GREASE Filtering | Yes | No |
| Complexity | More components | Simpler format |

## Use Cases

### 1. CDN Detection

Identify Content Delivery Networks serving your target:

```bash
# Basic CDN detection
cipherrun --ja3s --headers example.com

# Output CDN information
cipherrun --ja3s --headers example.com --json | jq '.cdn_detection'
```

**Common CDN Fingerprints:**
- Cloudflare: `623de93db17d313345d7ea481e7443cf`
- Akamai: `ada70206e40642a3e4461f35503241d5`
- AWS CloudFront: `e7d705a3286e19ea42f587b344ee6865`
- Fastly: `6734f37431670b3ab4292b8f60f29984`

### 2. Load Balancer Identification

Detect load balancers in front of servers:

```bash
# Identify load balancer
cipherrun --ja3s example.com --json | jq '.load_balancer_info'
```

**Common Load Balancer Fingerprints:**
- AWS ELB: `b742b407517bac9536a77a7b0fee28e9`
- HAProxy: `54e4acf23e0f075c44aa28b9bdd88456`
- F5 BIG-IP: `bc6c386f480ee97b9d9e52d472b772d8`
- Citrix NetScaler: `2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a`

### 3. Server Software Identification

Identify web server and application server software:

```bash
# Identify server software
cipherrun --ja3s example.com
```

**Common Server Fingerprints:**
- nginx: `7c02dbae662670040c7af9bd15fb7e2f`
- Apache: `73f4e03f59dc65a1e0c1c06875c2d2cb`
- Microsoft IIS 10: `579ccef312d18482fc42e2b822ca2430`
- Tomcat: `5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d`

### 4. Infrastructure Mapping

Map infrastructure changes over time:

```bash
# Track JA3S changes
cipherrun --ja3s example.com --store --db-config database.toml
cipherrun --changes example.com:443:30 --db-config database.toml
```

### 5. Security Monitoring

Detect infrastructure changes that may indicate compromise:

```bash
# Monitor for unexpected JA3S changes
cipherrun --ja3s example.com --json > baseline.json

# Later comparison
cipherrun --ja3s example.com --json > current.json
diff <(jq '.ja3s_hash' baseline.json) <(jq '.ja3s_hash' current.json)
```

## Usage Examples

### Basic JA3S Fingerprinting

```bash
# Generate JA3S fingerprint
cipherrun --ja3s example.com

# Output:
# JA3S Fingerprint:
#   JA3S Hash:      623de93db17d313345d7ea481e7443cf
#   SSL Version:    TLS 1.2 (771)
#   Cipher:         TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
#   Extensions:     5 extensions
#   Extension List: renegotiation_info, server_name, ec_point_formats, ...
#
# Database Match:
#   Name:           Cloudflare
#   Type:           CDN
#   Description:    Cloudflare edge server
```

### JSON Output

```bash
cipherrun --ja3s example.com --json-pretty
```

```json
{
  "ja3s_fingerprint": {
    "ja3s_string": "771,49199,65281-0-11-35-23",
    "ja3s_hash": "623de93db17d313345d7ea481e7443cf",
    "ssl_version": 771,
    "cipher": 49199,
    "extensions": [65281, 0, 11, 35, 23]
  },
  "ja3s_match": {
    "name": "Cloudflare",
    "type": "CDN",
    "description": "Cloudflare edge server",
    "common_ports": [443, 8443],
    "indicators": ["CF-RAY header", "cloudflare-nginx Server header"]
  },
  "cdn_detection": {
    "is_cdn": true,
    "cdn_provider": "Cloudflare",
    "confidence": 0.9,
    "indicators": ["JA3S signature matches Cloudflare", "Header: CF-RAY"]
  }
}
```

### Combined with HTTP Headers

```bash
# Maximum CDN/LB detection accuracy
cipherrun --ja3s --headers example.com
```

### Bulk Server Fingerprinting

```bash
# Scan multiple targets
cat targets.txt | xargs -I {} cipherrun --ja3s {} --json | \
  jq -r '{host: .target, ja3s: .ja3s_hash, server: .ja3s_match.name}'
```

### Find All Cloudflare Servers

```bash
# Identify all Cloudflare-protected targets
cat targets.txt | while read target; do
  result=$(cipherrun --ja3s "$target" --json 2>/dev/null)
  cdn=$(echo "$result" | jq -r '.cdn_detection.cdn_provider // "None"')
  if [ "$cdn" = "Cloudflare" ]; then
    echo "$target"
  fi
done
```

### ServerHello Raw Data

```bash
# Include raw ServerHello in output (for analysis)
cipherrun --ja3s --server-hello example.com --json > output.json
```

## CDN Detection

CipherRun combines JA3S fingerprints with HTTP headers for high-accuracy CDN detection.

### Detection Logic

1. **JA3S Signature Match** (70% confidence)
   - Match against known CDN fingerprints in database

2. **HTTP Header Analysis** (30% confidence per indicator)
   - Cloudflare: `CF-RAY`, `CF-Cache-Status`, `Server: cloudflare`
   - Akamai: `X-Akamai-*` headers
   - Fastly: `X-Fastly-*` headers
   - AWS CloudFront: `X-Amz-Cf-*` headers

3. **Combined Score**
   - Confidence capped at 1.0 (100%)
   - Multiple indicators increase confidence

### Example CDN Detection

```bash
cipherrun --ja3s --headers example.com --json | jq '.cdn_detection'
```

```json
{
  "is_cdn": true,
  "cdn_provider": "Cloudflare",
  "confidence": 1.0,
  "indicators": [
    "JA3S signature matches Cloudflare",
    "Header: CF-RAY",
    "Header: CF-Cache-Status",
    "Server header contains 'cloudflare'"
  ]
}
```

## Load Balancer Detection

### Supported Load Balancers

- **AWS ELB/ALB**: Detected via `X-Amzn-Trace-Id` header
- **HAProxy**: Detected via `X-HAProxy-*` headers
- **nginx**: Detected via `X-Upstream-*` headers
- **F5 BIG-IP**: JA3S signature match
- **Citrix NetScaler**: JA3S signature match

### Sticky Session Detection

CipherRun detects sticky sessions (session persistence) by analyzing:
- Cookie names containing: `route`, `sticky`, `persist`
- Load balancer-specific cookies (e.g., `BIGipServer*`)

## JA3S Database

CipherRun includes a comprehensive database of 50+ JA3S signatures.

### Database Structure

```json
{
  "623de93db17d313345d7ea481e7443cf": {
    "name": "Cloudflare",
    "type": "CDN",
    "description": "Cloudflare edge server",
    "common_ports": [443, 8443],
    "indicators": ["CF-RAY header", "cloudflare-nginx Server header"]
  }
}
```

### Categories

- **CDN**: Content delivery networks (Cloudflare, Akamai, etc.)
- **LoadBalancer**: Load balancers (AWS ELB, HAProxy, F5, etc.)
- **WebServer**: Web servers (nginx, Apache, IIS, etc.)
- **ApplicationServer**: App servers (Tomcat, WebSphere, etc.)
- **Firewall**: Web application firewalls (Imperva, Barracuda, etc.)
- **ReverseProxy**: Reverse proxies (Varnish, Envoy, etc.)

### Custom Database

You can provide a custom JA3S database:

```bash
cipherrun --ja3s --ja3s-db custom_signatures.json example.com
```

## Integration with Scanning

### Combined with Protocol/Cipher Testing

```bash
# Complete TLS analysis with JA3S
cipherrun --all --ja3s example.com
```

### Mass Scanning

```bash
# Scan multiple targets with JA3S
cipherrun --file targets.txt --ja3s --parallel --json > results.json
```

### Database Storage

```bash
# Store JA3S data for historical analysis
cipherrun --ja3s --store --db-config database.toml example.com
```

## Advanced Use Cases

### Infrastructure Change Detection

```bash
# Detect when CDN or load balancer changes
cipherrun --ja3s --store example.com --db-config database.toml

# Run periodically, then analyze changes
cipherrun --changes example.com:443:30 --db-config database.toml
```

### API Endpoints Behind CDNs

```bash
# Identify which API endpoints use which CDN
for endpoint in api.example.com api2.example.com api3.example.com; do
  echo -n "$endpoint: "
  cipherrun --ja3s "$endpoint" --json | jq -r '.cdn_detection.cdn_provider // "None"'
done
```

### Security Monitoring

```bash
# Alert on unexpected JA3S changes
EXPECTED_JA3S="623de93db17d313345d7ea481e7443cf"
CURRENT_JA3S=$(cipherrun --ja3s example.com --json | jq -r '.ja3s_hash')

if [ "$CURRENT_JA3S" != "$EXPECTED_JA3S" ]; then
  echo "WARNING: JA3S fingerprint changed!"
  echo "Expected: $EXPECTED_JA3S"
  echo "Current:  $CURRENT_JA3S"
fi
```

## Performance Considerations

- **Fast**: JA3S generation is very fast (single handshake)
- **Lightweight**: Minimal memory footprint
- **Parallel**: Can scan thousands of servers concurrently
- **Caching**: Results can be cached for repeated analysis

## Limitations

### TLS 1.3 Considerations

TLS 1.3 servers may have different fingerprints due to:
- Fewer cipher suites (only 5 defined)
- Different extension sets
- Encrypted extensions (not visible in ServerHello)

### Dynamic Fingerprints

Some servers may have dynamic fingerprints:
- Round-robin load balancers with different backends
- A/B testing different TLS configurations
- Geo-distributed servers with regional differences

### False Positives

JA3S matching can have false positives:
- Default configurations may match multiple servers
- Common cipher/extension combinations
- Shared infrastructure (hosting providers)

**Recommendation**: Always combine JA3S with HTTP header analysis for best accuracy.

## Technical Details

### ServerHello Parsing

CipherRun implements complete ServerHello parsing:
- TLS record layer (5 bytes)
- Handshake protocol (4 bytes)
- ServerHello message body
- Extension parsing with order preservation

### Extension Order

**Important**: Extension order MUST be preserved for accurate JA3S generation. CipherRun maintains exact ServerHello extension order.

### No GREASE Filtering

Unlike JA3 (client), JA3S does NOT filter GREASE values. All extension IDs from the server are included.

## References

- [JA3 GitHub Repository](https://github.com/salesforce/ja3)
- [JA3S Specification](https://github.com/salesforce/ja3/blob/master/JA3S.md)
- [TLS 1.2 RFC 5246](https://tools.ietf.org/html/rfc5246)
- [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
- [TLS Extensions Registry](https://www.iana.org/assignments/tls-extensiontype-values/)

## Contributing

To contribute new JA3S signatures to the database:

1. Capture real ServerHello from target server
2. Generate JA3S hash
3. Identify server type and indicators
4. Submit PR with signature to `data/ja3s_signatures.json`

Example signature:

```json
{
  "your_hash_here": {
    "name": "Server Name",
    "type": "CDN|LoadBalancer|WebServer|etc",
    "description": "Brief description",
    "common_ports": [443],
    "indicators": ["Specific headers or behaviors"]
  }
}
```

## Troubleshooting

### "Failed to generate JA3S fingerprint"

Possible causes:
- Connection timeout (increase with `--connect-timeout`)
- Server requires SNI (use `--sni-name`)
- STARTTLS required (use `--starttls`)
- Firewall blocking connection

### "No signature match found"

This is normal for:
- Custom server configurations
- New server software
- Regional variations
- Load balancer pools

Consider contributing the fingerprint to the database!

### Inconsistent JA3S Hashes

If you get different hashes for the same server:
- Load balancer with different backends
- A/B testing in progress
- Geo-distributed infrastructure
- Use `--test-all-ips` to test all resolved IPs

## See Also

- [JA3 Client Fingerprinting](JA3.md)
- [HTTP Headers Analysis](HTTP_HEADERS.md)
- [Certificate Analysis](CERTIFICATES.md)
- [Mass Scanning](MASS_SCANNING.md)
