// Hints system - Provide actionable advice for findings
// Helps users understand what to do about security issues

use crate::vulnerabilities::Severity;

/// Hint for a security finding
#[derive(Debug, Clone)]
pub struct Hint {
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub references: Vec<String>,
}

/// Get hint for a specific vulnerability
pub fn get_vulnerability_hint(vuln_name: &str) -> Option<Hint> {
    match vuln_name.to_lowercase().as_str() {
        "heartbleed" => Some(Hint {
            title: "Heartbleed Vulnerability".to_string(),
            description: "The server is vulnerable to Heartbleed (CVE-2014-0160), which allows attackers to read up to 64KB of memory at a time.".to_string(),
            remediation: "Upgrade OpenSSL to version 1.0.1g or later. Regenerate all private keys, certificates, and user credentials after patching.".to_string(),
            references: vec![
                "https://heartbleed.com/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2014-0160".to_string(),
            ],
        }),

        "poodle" => Some(Hint {
            title: "POODLE Attack".to_string(),
            description: "The server supports SSL 3.0 or vulnerable TLS implementations, allowing padding oracle attacks.".to_string(),
            remediation: "Disable SSL 3.0 completely. For TLS POODLE, ensure server rejects connections with CBC ciphers on TLS 1.0-1.2 or upgrade to TLS 1.3.".to_string(),
            references: vec![
                "https://www.openssl.org/~bodo/ssl-poodle.pdf".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2014-3566".to_string(),
            ],
        }),

        "beast" => Some(Hint {
            title: "BEAST Attack".to_string(),
            description: "The server supports TLS 1.0 with CBC ciphers, vulnerable to chosen-plaintext attacks.".to_string(),
            remediation: "Prioritize TLS 1.2+ with AEAD ciphers (AES-GCM, ChaCha20-Poly1305). If TLS 1.0 is required, enable 1/n-1 splitting or use RC4 as last resort.".to_string(),
            references: vec![
                "https://vnhacker.blogspot.com/2011/09/beast.html".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2011-3389".to_string(),
            ],
        }),

        "crime" => Some(Hint {
            title: "CRIME Attack".to_string(),
            description: "TLS or SPDY compression is enabled, allowing attackers to recover secrets through compression ratio analysis.".to_string(),
            remediation: "Disable TLS compression (OpenSSL: SSL_OP_NO_COMPRESSION). Disable SPDY header compression or upgrade to HTTP/2 with HPACK.".to_string(),
            references: vec![
                "https://en.wikipedia.org/wiki/CRIME".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2012-4929".to_string(),
            ],
        }),

        "breach" => Some(Hint {
            title: "BREACH Attack".to_string(),
            description: "HTTP compression is enabled with dynamic content, potentially exposing secrets through compression analysis.".to_string(),
            remediation: "Disable HTTP compression for responses containing secrets, implement CSRF tokens with random padding, or use same-origin policy restrictions.".to_string(),
            references: vec![
                "http://breachattack.com/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2013-3587".to_string(),
            ],
        }),

        "robot" => Some(Hint {
            title: "ROBOT Attack".to_string(),
            description: "The server is vulnerable to Bleichenbacher's RSA padding oracle attack, allowing decryption of TLS sessions.".to_string(),
            remediation: "Patch OpenSSL/TLS library to version with ROBOT fix. Prefer ECDHE key exchange over RSA. Monitor for suspicious connection patterns.".to_string(),
            references: vec![
                "https://robotattack.org/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2017-17382".to_string(),
            ],
        }),

        "drown" => Some(Hint {
            title: "DROWN Attack".to_string(),
            description: "SSLv2 is enabled, allowing cross-protocol attacks to decrypt TLS traffic using the same private key.".to_string(),
            remediation: "Disable SSLv2 completely on all servers using the private key. Regenerate certificates if SSLv2 was exposed to the internet.".to_string(),
            references: vec![
                "https://drownattack.com/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2016-0800".to_string(),
            ],
        }),

        "freak" => Some(Hint {
            title: "FREAK Attack".to_string(),
            description: "The server supports export-grade RSA ciphers (512-bit), allowing factorization attacks.".to_string(),
            remediation: "Disable all export ciphers (EXP-*). Ensure minimum RSA key size of 2048 bits. Upgrade to TLS 1.2+ with modern cipher suites.".to_string(),
            references: vec![
                "https://freakattack.com/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2015-0204".to_string(),
            ],
        }),

        "logjam" => Some(Hint {
            title: "LOGJAM Attack".to_string(),
            description: "The server supports weak Diffie-Hellman parameters, vulnerable to precomputation attacks.".to_string(),
            remediation: "Use DH parameters >= 2048 bits. Prefer ECDHE over DHE. Disable export DHE ciphers completely.".to_string(),
            references: vec![
                "https://weakdh.org/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2015-4000".to_string(),
            ],
        }),

        "sweet32" => Some(Hint {
            title: "Sweet32 Attack".to_string(),
            description: "The server supports 64-bit block ciphers (3DES, Blowfish), vulnerable to birthday attacks.".to_string(),
            remediation: "Disable 3DES and Blowfish ciphers. Use AES with 128-bit or 256-bit blocks. Prioritize AEAD cipher suites.".to_string(),
            references: vec![
                "https://sweet32.info/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2016-2183".to_string(),
            ],
        }),

        "rc4" => Some(Hint {
            title: "RC4 Cipher Weakness".to_string(),
            description: "RC4 stream cipher has statistical biases allowing recovery of plaintext (Appelbaum attack, RC4 NOMORE).".to_string(),
            remediation: "Disable all RC4 ciphers per RFC 7465. Use AES-GCM or ChaCha20-Poly1305 instead.".to_string(),
            references: vec![
                "https://www.rc4nomore.com/".to_string(),
                "https://tools.ietf.org/html/rfc7465".to_string(),
            ],
        }),

        "insecure_renegotiation" => Some(Hint {
            title: "Insecure Renegotiation".to_string(),
            description: "The server allows TLS renegotiation without RFC 5746 extension, vulnerable to MITM attacks.".to_string(),
            remediation: "Enable secure renegotiation (RFC 5746). Disable client-initiated renegotiation if not required.".to_string(),
            references: vec![
                "https://tools.ietf.org/html/rfc5746".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2009-3555".to_string(),
            ],
        }),

        _ => None,
    }
}

/// Get hint based on severity level
pub fn get_severity_hint(severity: Severity) -> Hint {
    match severity {
        Severity::Critical => Hint {
            title: "Critical Security Issue".to_string(),
            description: "This vulnerability can be easily exploited and has severe impact. Immediate action required.".to_string(),
            remediation: "Patch immediately. Consider taking the service offline until fixed if exposed to untrusted networks.".to_string(),
            references: vec![],
        },
        Severity::High => Hint {
            title: "High Severity Issue".to_string(),
            description: "This vulnerability poses significant risk and should be addressed urgently.".to_string(),
            remediation: "Schedule emergency patching within 24-48 hours. Implement compensating controls if immediate patching is not possible.".to_string(),
            references: vec![],
        },
        Severity::Medium => Hint {
            title: "Medium Severity Issue".to_string(),
            description: "This issue increases attack surface but requires specific conditions to exploit.".to_string(),
            remediation: "Include in next regular maintenance window. Monitor for exploitation attempts.".to_string(),
            references: vec![],
        },
        Severity::Low => Hint {
            title: "Low Severity Issue".to_string(),
            description: "This represents a minor security weakness or best practice deviation.".to_string(),
            remediation: "Address during regular updates. Document as known issue if remediation is not feasible.".to_string(),
            references: vec![],
        },
        Severity::Info => Hint {
            title: "Informational Finding".to_string(),
            description: "This is informational and does not represent a direct security risk.".to_string(),
            remediation: "Review for compliance with security policies. No immediate action required.".to_string(),
            references: vec![],
        },
    }
}

/// Format hint for display
pub fn format_hint(hint: &Hint) -> String {
    let mut output = String::new();

    output.push_str(&format!("\n💡 Hint: {}\n", hint.title));
    output.push_str(&format!("\n{}\n", hint.description));
    output.push_str(&format!("\n🔧 Remediation:\n{}\n", hint.remediation));

    if !hint.references.is_empty() {
        output.push_str("\n📚 References:\n");
        for reference in &hint.references {
            output.push_str(&format!("  - {}\n", reference));
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_vulnerability_hint() {
        let hint = get_vulnerability_hint("heartbleed").expect("test assertion should succeed");
        assert!(hint.title.contains("Heartbleed"));
        assert!(!hint.references.is_empty());
    }

    #[test]
    fn test_get_severity_hint() {
        let hint = get_severity_hint(Severity::Critical);
        assert!(hint.description.contains("Critical") || hint.description.contains("severe"));
    }

    #[test]
    fn test_format_hint() {
        let hint = Hint {
            title: "Test Vulnerability".to_string(),
            description: "Test description".to_string(),
            remediation: "Test remediation".to_string(),
            references: vec!["https://example.com".to_string()],
        };

        let formatted = format_hint(&hint);
        assert!(formatted.contains("Test Vulnerability"));
        assert!(formatted.contains("Test remediation"));
        assert!(formatted.contains("https://example.com"));
    }
}
