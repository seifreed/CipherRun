# JARM: TLS Server Active Fingerprinting

## Overview

JARM is an active TLS server fingerprinting technique developed by Salesforce that creates a unique fingerprint for TLS servers based on their response to multiple specially crafted TLS Client Hello packets. This implementation is based on the original [JARM specification](https://github.com/salesforce/jarm) and the [jarm-go reference implementation](https://github.com/hdm/jarm-go).

## What is JARM?

JARM works by sending 10 different TLS Client Hello packets to a target server and observing the responses. Each Client Hello varies in:

- TLS version (1.1, 1.2, 1.3)
- Cipher suite ordering (forward, reverse, top-half, bottom-half, middle-out)
- GREASE support (random values for forward compatibility testing)
- ALPN protocols (standard vs rare)
- Extension ordering

The server's responses are then hashed to create a unique 62-character fingerprint that can identify the server software, configuration, CDN, load balancer, or even malicious infrastructure.

## Why JARM?

### Server Identification
- Identify web servers (nginx, Apache, IIS)
- Detect CDNs (Cloudflare, Akamai, Fastly, CloudFront)
- Recognize load balancers (HAProxy, F5, AWS ELB)
- Discover reverse proxies and caching layers

### Threat Detection
- Identify malware Command & Control (C2) servers
- Detect phishing infrastructure
- Recognize known threat actor infrastructure
- Find malicious TLS endpoints

### Infrastructure Analysis
- Map Anycast deployments
- Understand service mesh configurations
- Analyze API gateway deployments
- Detect configuration changes over time

## How It Works

### The 10 JARM Probes

1. **TLS 1.2 - ALL ciphers, FORWARD order, NO_GREASE, ALPN, REVERSE extensions**
2. **TLS 1.2 - ALL ciphers, REVERSE order, NO_GREASE, ALPN, FORWARD extensions**
3. **TLS 1.2 - ALL ciphers, TOP_HALF order, NO_GREASE, NO_ALPN, FORWARD extensions**
4. **TLS 1.2 - ALL ciphers, BOTTOM_HALF order, NO_GREASE, RARE_ALPN, FORWARD extensions**
5. **TLS 1.2 - ALL ciphers, MIDDLE_OUT order, GREASE, RARE_ALPN, REVERSE extensions**
6. **TLS 1.1 - ALL ciphers, FORWARD order, NO_GREASE, ALPN, FORWARD extensions**
7. **TLS 1.3 - ALL ciphers, FORWARD order, NO_GREASE, ALPN, REVERSE extensions**
8. **TLS 1.3 - ALL ciphers, REVERSE order, NO_GREASE, ALPN, FORWARD extensions**
9. **TLS 1.3 - NO 1.3 ciphers, FORWARD order, NO_GREASE, ALPN, FORWARD extensions**
10. **TLS 1.3 - ALL ciphers, MIDDLE_OUT order, GREASE, ALPN, REVERSE extensions**

### Response Analysis

For each ServerHello response, JARM extracts:
- **Chosen cipher suite** (indexed from known cipher list)
- **Chosen TLS version** (encoded as single character)
- **ALPN protocol** (if negotiated)
- **Extension types** (order and presence)

### Hash Generation

The final JARM hash is a 62-character string:
- First 30 characters: Cipher and version data from all 10 probes (3 chars per probe)
- Last 32 characters: SHA256 hash of ALPN and extension information

## Usage

### Basic Fingerprinting

```bash
# Fingerprint a single target
cipherrun --jarm example.com:443

# Fingerprint with custom timeout
cipherrun --jarm --socket-timeout 5 example.com:443

# Mass fingerprinting from file
cipherrun --jarm -f targets.txt
```

### With Custom Signature Database

```bash
# Use custom JARM signature database
cipherrun --jarm --jarm-db custom_signatures.json example.com:443

# The database file should be JSON format:
# [
#   {
#     "hash": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
#     "name": "Cloudflare",
#     "server_type": "CDN",
#     "description": "Cloudflare CDN infrastructure",
#     "threat_level": null
#   }
# ]
```

### Integration with Other Features

```bash
# JARM + JA3S (complete server fingerprinting)
cipherrun --jarm --ja3s example.com:443

# JARM + JSON output
cipherrun --jarm --json results.json example.com:443

# JARM with vulnerability scanning
cipherrun --jarm -U example.com:443

# JARM with certificate analysis
cipherrun --jarm --show-certificates example.com:443
```

## Output Format

### Terminal Output

```
JARM Fingerprint
================================================================================
Hash:      27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d
Match:     Cloudflare
Type:      CDN
Details:   Cloudflare CDN infrastructure
```

### JSON Output

```json
{
  "jarm_fingerprint": {
    "hash": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
    "signature": {
      "hash": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
      "name": "Cloudflare",
      "server_type": "CDN",
      "description": "Cloudflare CDN infrastructure",
      "threat_level": null
    },
    "raw_responses": [
      "c02f|0303|h2|0000-0005-000a-000b-000d-0010-0017-0023-002b-002d-0033-ff01",
      "c030|0303|h2|0000-0005-000a-000b-000d-0010-0017-0023-002b-002d-0033-ff01",
      "|||",
      "|||",
      "c02f|0303|h2c|0000-0005-000a-000b-000d-0010-0017-0023-002b-002d-0033-ff01",
      "c013|0302||0000-0005-000b-0017-0023-ff01",
      "1301|0303|h2|0000-002b-0033",
      "1302|0303|h2|0000-002b-0033",
      "|||",
      "1301|0303|h2|0000-002b-0033"
    ]
  }
}
```

## Built-in Signature Database

CipherRun includes a comprehensive JARM signature database with 40+ known fingerprints:

### CDNs
- Cloudflare
- Akamai
- Fastly
- Amazon CloudFront
- Cloudflare Workers

### Web Servers
- nginx (various configurations)
- Apache HTTP Server
- Microsoft IIS
- Lighttpd
- Caddy

### Load Balancers
- HAProxy
- F5 BIG-IP
- AWS Elastic Load Balancer
- Google Cloud Load Balancer

### WAFs (Web Application Firewalls)
- Cloudflare WAF
- Imperva/Incapsula
- Sucuri WAF
- Barracuda WAF

### Application Servers
- Tomcat
- JBoss/WildFly
- Jetty
- WebLogic

### Reverse Proxies
- Varnish Cache
- Squid Proxy
- Traefik
- Envoy Proxy

### Threat Actors (Malware C2)
- **Cobalt Strike** (CVE-2021-31755 indicator)
- **Metasploit HTTPS** handler
- **Sliver C2** framework
- **Covenant C2** framework
- **TrickBot** C2 servers
- **Emotet** C2 infrastructure
- **QakBot/Qbot** C2
- **BazarLoader** C2

## Threat Detection Use Cases

### Identifying Malicious Infrastructure

JARM is particularly useful for identifying malicious infrastructure because many C2 frameworks use specific TLS implementations that create unique fingerprints:

```bash
# Scan suspicious domains
cipherrun --jarm suspicious-domain.com:443

# If output shows:
# Match: Cobalt Strike C2
# Type: Malware C2
# Threat Level: critical
```

### Hunting for Specific Threats

```bash
# Mass scan potential C2 infrastructure
cipherrun --jarm -f suspected_c2_ips.txt --json results.json

# Filter for threat signatures
jq '.[] | select(.jarm_fingerprint.signature.threat_level != null)' results.json
```

### Monitoring for Infrastructure Changes

```bash
# Store results in database
cipherrun --jarm --store --db-config database.toml example.com:443

# Check for changes over time
cipherrun --changes example.com:443:30 --db-config database.toml
```

## Understanding JARM Hashes

A JARM hash like `27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d` breaks down as follows:

### First 30 Characters (Probe Responses)
- Positions 0-2: Probe 1 (cipher index + version)
- Positions 3-5: Probe 2
- Positions 6-8: Probe 3
- ... and so on for all 10 probes

### Last 32 Characters (ALPN/Extensions Hash)
- SHA256 hash of concatenated ALPN and extension data from all probes

### Special Values
- `00` - No response or connection failure
- `|||` - Failed probe (no valid ServerHello)
- All zeros - All probes failed (server offline or blocking)

## Cipher Ordering Modes

JARM uses different cipher ordering strategies to elicit varying responses:

- **FORWARD**: Original order (strongest to weakest)
- **REVERSE**: Reversed order (weakest to strongest)
- **TOP_HALF**: First half of cipher list
- **BOTTOM_HALF**: Second half of cipher list
- **MIDDLE_OUT**: Starts from middle, alternates outward

Different servers prioritize ciphers differently, revealing configuration details.

## GREASE Support

GREASE (Generate Random Extensions And Sustain Extensibility) values are random values used to test server tolerance for unknown extensions. JARM includes GREASE in some probes to:

- Test server RFC compliance
- Identify overly strict implementations
- Detect specific server software behaviors

## Limitations

### False Positives
- Some servers may share JARM hashes
- Configuration changes can alter fingerprints
- Cloud providers may use multiple configurations

### Network Conditions
- Timeouts can affect probe success
- Load balancers may distribute probes to different backends
- Rate limiting can impact results

### Countermeasures
- Attackers can modify C2 TLS configurations
- JARM randomization tools exist
- Custom TLS implementations can spoof fingerprints

## Best Practices

### For Security Analysis

1. **Combine with other signals**: Use JARM alongside JA3S, certificates, HTTP headers
2. **Monitor over time**: Track changes to detect compromises
3. **Context matters**: Consider IP reputation, DNS records, certificate details
4. **Verify matches**: Don't rely solely on JARM for threat attribution

### For Infrastructure Mapping

1. **Scan all endpoints**: Different ports may reveal different infrastructure
2. **Test IP ranges**: Anycast deployments may show consistent fingerprints
3. **Document baselines**: Know your infrastructure's normal JARM values
4. **Track changes**: Alert on unexpected fingerprint modifications

### For Threat Hunting

1. **Build custom databases**: Add organization-specific threat signatures
2. **Correlate with CTI**: Cross-reference with threat intelligence feeds
3. **Automate scanning**: Regularly fingerprint suspicious infrastructure
4. **Share fingerprints**: Contribute to community threat databases

## Performance Considerations

- Each JARM scan sends 10 separate connections
- Total time depends on server response time and timeout settings
- Recommended timeout: 3-5 seconds per probe
- Mass scanning: Use `--parallel` for better performance
- Rate limiting: Consider `--delay` to avoid triggering IDS/IPS

## Technical Details

### Cipher Lists

**ALL Ciphers** (includes TLS 1.3):
- 69 total cipher suites
- Covers TLS 1.0 through TLS 1.3
- Includes both modern and legacy ciphers

**NO1.3 Ciphers**:
- Same list without TLS 1.3 cipher suites (0x13xx)
- 64 cipher suites

### Extensions Used

JARM Client Hello includes:
- Server Name Indication (SNI)
- Extended Master Secret
- Session Ticket
- Renegotiation Info
- Supported Groups (EC curves, DH groups)
- EC Point Formats
- ALPN (application layer protocol negotiation)
- Signature Algorithms
- Key Share (TLS 1.3)
- PSK Key Exchange Modes (TLS 1.3)
- Supported Versions (TLS 1.3)

## References

- [Original JARM Paper (Salesforce)](https://github.com/salesforce/jarm)
- [JARM Randomizer](https://github.com/salesforce/jarm/blob/master/jarm_randomizer.py)
- [jarm-go Implementation](https://github.com/hdm/jarm-go)
- [JARM Fingerprints Database](https://github.com/salesforce/jarm/blob/master/fingerprints)

## Contributing Signatures

To contribute new JARM signatures to the database:

1. Fingerprint the server: `cipherrun --jarm target:443 --json output.json`
2. Verify the fingerprint is unique
3. Add entry to `data/jarm_signatures.json`:

```json
{
  "hash": "your_jarm_hash_here",
  "name": "Server Name",
  "server_type": "Category",
  "description": "Detailed description",
  "threat_level": null or "low|medium|high|critical"
}
```

4. Submit a pull request with:
   - The new signature
   - Evidence of the server type
   - Multiple samples if possible

## Examples

### Example 1: Detecting Cloudflare

```bash
$ cipherrun --jarm cloudflare.com:443

JARM Fingerprint: 27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d
Match: Cloudflare (CDN)
```

### Example 2: Finding Cobalt Strike C2

```bash
$ cipherrun --jarm suspicious-c2.example.com:443

JARM Fingerprint: 2ad2ad0002ad2ad0002ad2ad2ad2ad8c5ba1850e6f500d37a6a1be3a0a1f0e
Match: Cobalt Strike C2 (Malware C2)
Threat Level: CRITICAL
Description: Cobalt Strike default HTTPS Beacon (CVE-2021-31755 indicator)
```

### Example 3: Mass Infrastructure Mapping

```bash
$ cat targets.txt
cdn-endpoint1.example.com:443
cdn-endpoint2.example.com:443
origin-server.example.com:443

$ cipherrun --jarm -f targets.txt --json results.json --parallel

# Analyze results
$ jq -r '.[] | "\(.target): \(.jarm_fingerprint.signature.name)"' results.json
cdn-endpoint1.example.com:443: Cloudflare
cdn-endpoint2.example.com:443: Cloudflare
origin-server.example.com:443: nginx
```

## FAQ

**Q: Is JARM passive or active?**
A: JARM is active - it sends Client Hello packets to the server.

**Q: Can JARM detect all malware C2?**
A: No, only C2 servers using known TLS configurations. Custom implementations may not match.

**Q: How accurate is JARM?**
A: Very accurate for identifying specific software versions and configurations, but can have false positives.

**Q: Can attackers evade JARM detection?**
A: Yes, by customizing TLS implementations or using JARM randomization tools.

**Q: Does JARM work with STARTTLS?**
A: Yes, use with `--starttls` flags: `cipherrun --jarm --starttls-smtp mail.example.com:25`

**Q: What's the difference between JARM and JA3S?**
A: JARM actively probes with 10 different Client Hellos; JA3S passively observes a single ServerHello.

**Q: How often should I update JARM signatures?**
A: Monitor the community database monthly; major infrastructure changes happen quarterly.

## Troubleshooting

### All Probes Fail (Zero Hash)

```bash
# Common causes:
# 1. Firewall blocking
# 2. Server offline
# 3. Timeout too short
# 4. Rate limiting

# Solutions:
cipherrun --jarm --socket-timeout 10 target:443
cipherrun --jarm --delay 1s target:443
```

### Inconsistent Fingerprints

```bash
# Possible causes:
# 1. Load balancer distributing to different backends
# 2. Anycast with different configurations
# 3. Time-based configuration changes

# Collect multiple samples:
for i in {1..10}; do
  cipherrun --jarm target:443 --json "sample_$i.json"
  sleep 5
done
```

### No Signature Match

```bash
# The fingerprint is unique or unknown
# 1. Verify it's not a false positive
# 2. Correlate with other data (certificates, HTTP headers)
# 3. Consider adding to custom database
# 4. Share with community if significant
```
