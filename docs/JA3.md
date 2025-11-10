# JA3 TLS Client Fingerprinting

## Overview

JA3 is a method for creating SSL/TLS client fingerprints that are easy to produce and can be easily shared for threat intelligence. CipherRun implements complete JA3 fingerprinting to identify TLS clients and detect potentially malicious connections.

## What is JA3?

JA3 is a technique developed by Salesforce that creates fingerprints of TLS clients by collecting specific parameters from the TLS ClientHello message. These fingerprints can identify specific applications, tools, or malware families based on their TLS handshake characteristics.

### JA3 Algorithm

The JA3 fingerprint is created by concatenating specific TLS ClientHello parameters into a string, then generating an MD5 hash of that string:

```
JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
```

**Components:**

1. **SSLVersion**: TLS version in decimal format (e.g., 771 for TLS 1.2)
2. **Ciphers**: Comma-separated list of cipher suite values in decimal
3. **Extensions**: Comma-separated list of extension IDs in decimal
4. **EllipticCurves**: Comma-separated list of supported group/curve IDs
5. **EllipticCurvePointFormats**: Comma-separated list of EC point format IDs

**Example JA3 String:**
```
771,49195-49199-49196-49200-159-107,0-10-11-13-35-23,23-24-25,0
```

**Example JA3 Hash:**
```
773906b0efdefa24a7f2b8eb6985bf37
```

### GREASE Filtering

GREASE (Generate Random Extensions And Sustain Extensibility) values are filtered out before generating the JA3 fingerprint. GREASE values follow the pattern `0x0a0a`, `0x1a1a`, `0x2a2a`, etc. and are used by some clients to prevent ossification of TLS implementations.

## Usage

### Basic JA3 Fingerprinting

Generate JA3 fingerprint for a target:

```bash
cipherrun --ja3 example.com
```

**Output:**
```
JA3 Fingerprint:
  JA3 Hash:       773906b0efdefa24a7f2b8eb6985bf37
  SSL Version:    TLS 1.2 (771)
  Cipher Suites:  15 suites
  Extensions:     10 extensions
  Curves:         3 curves
  Point Formats:  1 formats
  Named Curves:   X25519, secp256r1, secp384r1

  JA3 String:
  771,49195-49199-49196-49200-159-107,0-10-11-13-35-23,23-24-25,0

Database Match:
  Name:         Chrome 120
  Category:     Browser
  Description:  Google Chrome 120.x on Windows
  Threat Level: none
```

### Include ClientHello in JSON

Capture the raw ClientHello message in JSON output:

```bash
cipherrun --ja3 --client-hello --json results.json example.com
```

### Custom JA3 Database

Use a custom signature database:

```bash
cipherrun --ja3 --ja3-db custom_signatures.json example.com
```

### JSON Output Format

The JSON output includes complete JA3 data:

```json
{
  "ja3_fingerprint": {
    "ja3_string": "771,49195-49199-49196-49200-159-107,0-10-11-13-35-23,23-24-25,0",
    "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
    "ssl_version": 771,
    "ciphers": [49195, 49199, 49196, 49200, 159, 107],
    "extensions": [0, 10, 11, 13, 35, 23],
    "curves": [23, 24, 25],
    "point_formats": [0]
  },
  "ja3_match": {
    "name": "Chrome 120",
    "category": "Browser",
    "description": "Google Chrome 120.x on Windows",
    "threat_level": "none"
  },
  "client_hello_raw": "160303..." // Base64 encoded (if --client-hello is used)
}
```

## JA3 Signature Database

CipherRun includes a built-in database of known JA3 fingerprints for common clients and malware.

### Database Format

The signature database is a JSON file with the following structure:

```json
{
  "773906b0efdefa24a7f2b8eb6985bf37": {
    "name": "Chrome 120",
    "category": "Browser",
    "description": "Google Chrome 120.x on Windows",
    "threat_level": "none"
  },
  "a0e9f5d64349fb13191bc781f81f42e1": {
    "name": "Cobalt Strike",
    "category": "Malware",
    "description": "Cobalt Strike C2 beacon",
    "threat_level": "high"
  }
}
```

### Categories

- **Browser**: Web browsers (Chrome, Firefox, Safari, Edge)
- **Tool**: Security/network tools (curl, wget, nmap, metasploit)
- **Library**: Programming language libraries (Python requests, Go HTTP, Java)
- **Mobile**: Mobile platforms (Android, iOS)
- **Malware**: Malicious software (trojans, stealers, RATs)

### Threat Levels

- **none**: Benign/legitimate applications
- **low**: Potentially unwanted programs
- **medium**: Security tools (can be used for good or bad)
- **high**: Known malware/hacking tools
- **critical**: Advanced persistent threats (APTs), banking trojans

## Known Signatures

### Legitimate Clients

| JA3 Hash | Name | Category |
|----------|------|----------|
| 773906b0efdefa24a7f2b8eb6985bf37 | Chrome 120 | Browser |
| 51c64c77e60f3980eea90869b68c58a8 | Firefox 121 | Browser |
| ada70206e40642a3e4461f35503241d5 | Safari 17 | Browser |
| 6734f37431670b3ab4292b8f60f29984 | curl | Tool |
| e35df3e00ca4ef31d42b34bebaa2f86e | Python Requests | Library |
| b32309a26951912be7dba376398abc3b | OpenSSL | Library |

### Malware Signatures

| JA3 Hash | Name | Threat Level |
|----------|------|--------------|
| a0e9f5d64349fb13191bc781f81f42e1 | Cobalt Strike | High |
| bc6c386f480ee97b9d9e52d472b772d8 | Trickbot | Critical |
| 72a589da586844d7f0818ce684948eea | Dridex | Critical |
| 7dd50e112cd23734a310b90fa9439954 | Emotet | Critical |
| 9e5a6f8e7d6c5b4a3c2b1d0e9f8e7d6c | QakBot | Critical |

## Threat Detection Use Cases

### 1. Malware C2 Detection

Identify malware command-and-control beacons by their JA3 fingerprints:

```bash
# Scan multiple targets and check for malware signatures
cat targets.txt | xargs -I {} cipherrun --ja3 {} --json | \
  jq -r 'select(.ja3_match.threat_level == "high" or .ja3_match.threat_level == "critical") | .target'
```

### 2. Security Tool Detection

Identify scanning/enumeration tools:

```bash
# Detect Metasploit, nmap, etc.
cipherrun --ja3 suspicious-server.com --json | jq '.ja3_match.category'
```

### 3. Application Inventory

Build an inventory of TLS clients in your environment:

```bash
# Collect all JA3 hashes
cipherrun --ja3 internal-service.com --json | jq -r '.ja3_fingerprint.ja3_hash' >> ja3_inventory.txt
```

### 4. Anomaly Detection

Detect unknown or unusual TLS clients:

```bash
# Find connections with no database match
cipherrun --ja3 example.com --json | jq 'select(.ja3_match == null)'
```

## Examples

### Example 1: Basic Fingerprinting

```bash
$ cipherrun --ja3 badssl.com

JA3 Fingerprint:
  JA3 Hash:       771,49195-49199-49196-49200-159-107,0-10-11-13-35-23,23-24-25,0
  SSL Version:    TLS 1.2 (771)
  Cipher Suites:  15 suites
  Extensions:     10 extensions
  Curves:         3 curves (X25519, secp256r1, secp384r1)
  Point Formats:  1 formats

Database Match:
  Name:         CipherRun (rustls)
  Category:     Tool
  Threat Level: none
```

### Example 2: Bulk Fingerprinting

```bash
# Fingerprint multiple targets
$ cat targets.txt
example.com
google.com
github.com

$ cat targets.txt | while read target; do
    echo "Scanning $target..."
    cipherrun --ja3 $target --json | jq -r '.ja3_fingerprint.ja3_hash'
done

773906b0efdefa24a7f2b8eb6985bf37
773906b0efdefa24a7f2b8eb6985bf37
773906b0efdefa24a7f2b8eb6985bf37
```

### Example 3: Threat Hunting

```bash
# Hunt for Cobalt Strike beacons
$ cipherrun --ja3 suspicious-c2.com --json | \
  jq 'select(.ja3_fingerprint.ja3_hash == "a0e9f5d64349fb13191bc781f81f42e1")'

{
  "ja3_match": {
    "name": "Cobalt Strike",
    "category": "Malware",
    "threat_level": "high"
  }
}
```

### Example 4: Compare Multiple Scans

```bash
# Compare JA3 across different scan times
$ cipherrun --ja3 api.example.com --json > scan1.json
$ sleep 3600
$ cipherrun --ja3 api.example.com --json > scan2.json
$ diff <(jq -r '.ja3_fingerprint.ja3_hash' scan1.json) \
       <(jq -r '.ja3_fingerprint.ja3_hash' scan2.json)
```

## Integration with SIEM/IDS

### Splunk

```spl
index=tls sourcetype=cipherrun
| stats count by ja3_hash, ja3_match.name, ja3_match.threat_level
| where threat_level IN ("high", "critical")
```

### Elastic Stack

```json
GET /tls-scans/_search
{
  "query": {
    "bool": {
      "should": [
        { "term": { "ja3_match.threat_level": "high" }},
        { "term": { "ja3_match.threat_level": "critical" }}
      ]
    }
  }
}
```

### Zeek/Bro IDS

Export JA3 hashes for correlation with Zeek logs:

```bash
cipherrun --ja3 example.com --json | jq -r '.ja3_fingerprint.ja3_hash' > zeek_watchlist.txt
```

## Custom Signature Database

Create your own JA3 signature database:

```json
{
  "custom_hash_1234": {
    "name": "Internal App v2.1",
    "category": "Internal",
    "description": "Company internal application",
    "threat_level": "none"
  },
  "custom_hash_5678": {
    "name": "Legacy API Client",
    "category": "Internal",
    "description": "Legacy API client (needs upgrade)",
    "threat_level": "low"
  }
}
```

Use it:

```bash
cipherrun --ja3 --ja3-db my_signatures.json internal-api.company.com
```

## Limitations

1. **Client Fingerprinting**: JA3 fingerprints the **scanner's own TLS client** (CipherRun), not the server
2. **Randomization**: Some clients randomize their TLS parameters, making fingerprinting less reliable
3. **Version Changes**: Client fingerprints change with software updates
4. **False Positives**: Multiple applications may share the same JA3 fingerprint
5. **GREASE Impact**: Clients using GREASE may produce varying fingerprints

## References

- [JA3: SSL/TLS Client Fingerprinting](https://github.com/salesforce/ja3)
- [RFC 8701: GREASE](https://tools.ietf.org/html/rfc8701)
- [TLS 1.3 (RFC 8446)](https://tools.ietf.org/html/rfc8446)
- [JA3 Database](https://github.com/salesforce/ja3/blob/master/lists/osx-nix-ja3.csv)

## Contributing Signatures

To contribute new JA3 signatures to CipherRun:

1. Identify the client and its exact version
2. Generate the JA3 fingerprint
3. Verify the fingerprint is consistent across multiple connections
4. Submit a pull request with the signature added to `data/ja3_signatures.json`

**Signature Requirements:**

- Accurate client name and version
- Correct category assignment
- Detailed description
- Appropriate threat level
- Verification from multiple sources

## See Also

- [JA3S Server Fingerprinting](JA3S.md) - Fingerprint TLS servers
- [Certificate Analysis](CERTIFICATES.md) - Certificate validation and trust
- [Vulnerability Testing](VULNERABILITIES.md) - TLS vulnerability detection
