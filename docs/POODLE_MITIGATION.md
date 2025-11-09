# POODLE Variants Mitigation Guide

## Quick Reference

| Variant | CVE | Severity | Immediate Action | Long-term Solution |
|---------|-----|----------|------------------|-------------------|
| Classic POODLE (SSLv3) | CVE-2014-3566 | HIGH | Disable SSL 3.0 | Remove SSL 3.0 support |
| TLS POODLE | CVE-2014-8730 | HIGH | Disable CBC ciphers | Update TLS stack, use TLS 1.3 |
| Zombie POODLE | CVE-2019-5592 | HIGH | Disable CBC ciphers | Update F5/Citrix firmware |
| GOLDENDOODLE | CVE-2019-5592 | HIGH | Disable CBC ciphers | Constant-time implementation |
| Sleeping POODLE | CVE-2019-5592 | MEDIUM | Disable CBC ciphers | Constant-time implementation |
| OpenSSL 0-Length | CVE-2011-4576 | HIGH | Update OpenSSL | Use OpenSSL 1.1.1+ |

## Universal Mitigation Strategy

The most effective mitigation for all POODLE variants:

### 1. Disable CBC Cipher Suites

**Rationale**: All POODLE variants exploit CBC mode padding validation flaws. AEAD ciphers (GCM, ChaCha20-Poly1305) don't use padding and are immune.

**Recommended Cipher Suites** (TLS 1.2+):
```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
```

**Remove These CBC Ciphers**:
```
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
... (all *_CBC_* ciphers)
```

### 2. Enable TLS 1.3

**Rationale**: TLS 1.3 removes CBC cipher support entirely and only supports AEAD ciphers.

**Benefits**:
- No CBC mode = immune to all POODLE variants
- Faster handshakes (1-RTT, 0-RTT)
- Improved forward secrecy
- Simplified cipher suite selection

**TLS 1.3 Cipher Suites**:
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

### 3. Disable Legacy Protocols

**Remove**:
- SSL 2.0
- SSL 3.0
- TLS 1.0
- TLS 1.1 (deprecated as of 2020)

**Keep**:
- TLS 1.2 (with GCM/ChaCha20 only)
- TLS 1.3

## Platform-Specific Mitigation

### Apache Web Server

**Location**: `/etc/apache2/mods-enabled/ssl.conf` or `/etc/httpd/conf.d/ssl.conf`

```apache
# Disable SSL 2.0, 3.0, TLS 1.0, TLS 1.1
SSLProtocol -all +TLSv1.2 +TLSv1.3

# Use only AEAD ciphers (no CBC)
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305

# TLS 1.3 ciphers (if supported)
SSLCipherSuite TLSv1.3 TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

# Honor server cipher order
SSLHonorCipherOrder on

# Restart Apache
# systemctl restart apache2
```

### Nginx

**Location**: `/etc/nginx/nginx.conf` or `/etc/nginx/sites-available/default`

```nginx
# Disable old protocols
ssl_protocols TLSv1.2 TLSv1.3;

# Use only AEAD ciphers
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

# Prefer server ciphers
ssl_prefer_server_ciphers on;

# Reload Nginx
# nginx -s reload
```

### HAProxy

**Location**: `/etc/haproxy/haproxy.cfg`

```haproxy
# Frontend/Backend SSL configuration
frontend https-in
    bind *:443 ssl crt /etc/ssl/certs/cert.pem ssl-min-ver TLSv1.2 ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# Restart HAProxy
# systemctl restart haproxy
```

### F5 BIG-IP (Zombie POODLE, GOLDENDOODLE)

**Affected Versions**:
- BIG-IP 11.x - 14.x (specific builds vulnerable)

**Mitigation**:

1. **Update Firmware**:
   - Check F5 Security Advisory: K50233160
   - Update to patched versions:
     - 14.1.0.3+
     - 13.1.1.5+
     - 12.1.4.1+
     - 11.6.4.1+

2. **Disable CBC Ciphers** (immediate workaround):
   ```
   tmsh modify ltm profile client-ssl <profile_name> ciphers 'ECDHE+AES-GCM:DHE+AES-GCM:AES-GCM'
   ```

3. **Verify**:
   ```
   tmsh list ltm profile client-ssl <profile_name> ciphers
   ```

### Citrix NetScaler/ADC (Zombie POODLE, GOLDENDOODLE)

**Affected Versions**:
- NetScaler 11.x, 12.x, 13.x (specific builds)

**Mitigation**:

1. **Update Firmware**:
   - Check Citrix Security Bulletin: CTX240139
   - Update to patched versions

2. **Disable CBC via CLI**:
   ```
   bind ssl vserver <vserver_name> -cipherName ECDHE_RSA_AES128_GCM_SHA256
   bind ssl vserver <vserver_name> -cipherName ECDHE_RSA_AES256_GCM_SHA384
   unbind ssl vserver <vserver_name> -cipherName <CBC_cipher_name>
   ```

3. **Verify**:
   ```
   show ssl vserver <vserver_name>
   ```

### OpenSSL 0-Length Fragment (CVE-2011-4576)

**Affected Versions**:
- OpenSSL < 0.9.8s
- OpenSSL 1.0.0 - 1.0.0e

**Mitigation**:

1. **Check Version**:
   ```bash
   openssl version
   ```

2. **Update OpenSSL**:

   **Debian/Ubuntu**:
   ```bash
   apt-get update
   apt-get install openssl libssl-dev
   ```

   **RHEL/CentOS**:
   ```bash
   yum update openssl openssl-devel
   ```

   **Build from Source**:
   ```bash
   wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz
   tar xzf openssl-1.1.1w.tar.gz
   cd openssl-1.1.1w
   ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
   make
   make test
   sudo make install
   ```

3. **Restart Services**:
   ```bash
   systemctl restart apache2
   systemctl restart nginx
   systemctl restart httpd
   ```

## Verification After Mitigation

### Using CipherRun

```bash
# Test all POODLE variants
cipherrun scan https://your-server.com

# Test specific vulnerability
cipherrun vuln --target your-server.com:443 --vuln poodle
```

**Expected Output** (after mitigation):
```
[SAFE] POODLE (SSLv3) - CVE-2014-3566
       Server does not support SSLv3

[SAFE] Zombie POODLE - CVE-2019-5592
       CBC ciphers not supported - not vulnerable

[SAFE] GOLDENDOODLE - CVE-2019-5592
       CBC ciphers not supported - not vulnerable

[SAFE] Sleeping POODLE - CVE-2019-5592
       CBC ciphers not supported - not vulnerable

[SAFE] OpenSSL 0-Length Fragment - CVE-2011-4576
       Server properly rejects zero-length records
```

### Using OpenSSL CLI

**Test CBC Cipher Support**:
```bash
# Try to connect with CBC cipher
openssl s_client -connect your-server.com:443 -cipher AES128-SHA

# Should fail with:
# error: no ciphers available
```

**Test Protocol Support**:
```bash
# Test SSL 3.0 (should fail)
openssl s_client -connect your-server.com:443 -ssl3

# Test TLS 1.2 (should succeed)
openssl s_client -connect your-server.com:443 -tls1_2

# Test TLS 1.3 (should succeed if enabled)
openssl s_client -connect your-server.com:443 -tls1_3
```

### Using nmap

```bash
# Scan for SSL/TLS versions
nmap --script ssl-enum-ciphers -p 443 your-server.com

# Check for POODLE
nmap --script ssl-poodle -p 443 your-server.com
```

### Using testssl.sh

```bash
git clone https://github.com/drwetter/testssl.sh
cd testssl.sh
./testssl.sh -P your-server.com:443

# Look for:
# - POODLE, SSL ... not vulnerable
# - CBC ciphers ... not offered
```

### Using SSL Labs

1. Visit: https://www.ssllabs.com/ssltest/
2. Enter your domain
3. Wait for analysis
4. Check "Protocol Details" section:
   - "POODLE (SSLv3)" should be "No"
   - "POODLE (TLS)" should be "No"
   - "Zombie POODLE" should be "No"
   - CBC ciphers should not appear in supported cipher list

## Compliance Requirements

### PCI DSS 4.0

**Requirement 4.2.1**: Strong cryptography must be used

**POODLE Impact**:
- SSL 3.0 is explicitly forbidden
- CBC ciphers not recommended
- TLS 1.2+ required

**Compliance Steps**:
1. Disable SSL 2.0, 3.0, TLS 1.0, TLS 1.1
2. Remove all CBC cipher suites
3. Document cipher suite selection
4. Quarterly vulnerability scans

### NIST SP 800-52 Rev. 2

**Guidelines**:
- TLS 1.2 minimum (TLS 1.3 preferred)
- Only AEAD ciphers for new systems
- CBC ciphers deprecated

**POODLE Mitigation Alignment**:
- Disabling CBC ciphers aligns with NIST recommendations
- TLS 1.3 adoption exceeds minimum requirements

### HIPAA Security Rule

**Technical Safeguards** (§164.312(a)(2)(iv)):
- Encryption and decryption mechanisms

**POODLE Impact**:
- Vulnerable encryption = non-compliance
- Must use current cryptographic standards

## Monitoring and Maintenance

### Continuous Monitoring

**Weekly**:
```bash
# Automated scan
cipherrun scan https://your-servers.txt --output report.json
```

**Monthly**:
- Review SSL Labs grade
- Check for new CVEs
- Update cipher suite preferences

**Quarterly**:
- Full penetration test
- Review TLS library versions
- Update security policies

### Logging and Alerting

**Log TLS Handshake Failures**:

**Apache**:
```apache
LogLevel ssl:info
CustomLog logs/ssl_handshake.log "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x %r"
```

**Nginx**:
```nginx
error_log /var/log/nginx/ssl_error.log info;
```

**Alert on CBC Connections** (if temporarily enabled for compatibility):
```bash
# Monitor for CBC cipher usage
tail -f /var/log/nginx/access.log | grep "CBC"
```

### Update Strategy

**Immediate** (Critical CVEs):
- Apply security patches within 24 hours
- Test in staging first
- Deploy to production
- Verify with CipherRun

**Regular** (Quarterly):
- Update OpenSSL/TLS libraries
- Review cipher suite best practices
- Benchmark performance impact
- Update documentation

## Compatibility Considerations

### Client Compatibility After Removing CBC

**Impact**: Removing CBC ciphers may affect very old clients

**Affected Clients**:
- Windows XP / IE8 (End of Life)
- Android 4.3 and older (< 1% usage)
- Java 7 and older
- Python 2.7.8 and older

**Mitigation for Legacy Clients**:

**Option 1: Dual Configuration** (not recommended)
```
# Modern clients (TLS 1.3, AEAD only)
server {
    listen 443 ssl http2;
    ssl_protocols TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
}

# Legacy clients (TLS 1.2, includes CBC)
server {
    listen 8443 ssl;
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-CBC-SHA';
}
```

**Option 2: Client Upgrade Policy** (recommended)
1. Notify users of minimum client requirements
2. Provide upgrade instructions
3. Set deprecation timeline (e.g., 90 days)
4. Remove CBC support after timeline

**Option 3: Accept Risk** (temporary)
1. Document risk acceptance
2. Set automatic removal date
3. Monitor usage statistics
4. Remove when usage < 0.1%

## Performance Impact

**Impact of AEAD Ciphers**:
- AES-GCM: Hardware accelerated (AES-NI) = negligible impact
- ChaCha20-Poly1305: Fast on mobile devices, slight CPU increase on servers
- TLS 1.3: 30% faster handshakes than TLS 1.2

**Benchmarking**:
```bash
# Apache Bench with TLS 1.3
ab -n 1000 -c 10 https://your-server.com/

# OpenSSL speed test
openssl speed -evp aes-128-gcm
openssl speed -evp chacha20-poly1305
```

## Emergency Rollback Plan

If issues arise after mitigation:

1. **Identify Problem**:
   - Check error logs
   - Identify affected client versions
   - Measure impact (% of traffic)

2. **Temporary Rollback**:
   ```bash
   # Apache - re-enable CBC temporarily
   SSLCipherSuite HIGH:!aNULL:!MD5
   systemctl reload apache2
   ```

3. **Root Cause Analysis**:
   - Identify incompatible clients
   - Check for misconfiguration
   - Verify TLS library versions

4. **Permanent Fix**:
   - Update client requirements
   - Fix configuration errors
   - Re-apply mitigation

5. **Document Incident**:
   - Timeline
   - Root cause
   - Lessons learned
   - Prevention steps

## Additional Resources

### Tools
- **CipherRun**: https://github.com/seifreed/cipherrun
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **testssl.sh**: https://github.com/drwetter/testssl.sh
- **Mozilla SSL Config Generator**: https://ssl-config.mozilla.org/

### Documentation
- **NIST SP 800-52r2**: https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final
- **RFC 7568** (SSL 3.0 deprecation): https://tools.ietf.org/html/rfc7568
- **RFC 8446** (TLS 1.3): https://tools.ietf.org/html/rfc8446

### Vendor Advisories
- **F5 K50233160**: https://support.f5.com/csp/article/K50233160
- **Citrix CTX240139**: https://support.citrix.com/article/CTX240139
- **OpenSSL Security**: https://www.openssl.org/news/vulnerabilities.html

## Support

For questions or issues:
- GitHub Issues: https://github.com/seifreed/cipherrun/issues
- Security Contact: security@cipherrun.org
- Documentation: https://docs.cipherrun.org

---

**Document Version**: 1.0
**Last Updated**: 2025-01-09
**Author**: Marc Rivero López
**License**: GPL-3.0
