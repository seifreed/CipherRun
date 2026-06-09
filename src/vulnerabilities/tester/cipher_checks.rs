use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::Protocol;
use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

pub(crate) fn summary_has_cipher_evidence(summary: &ProtocolCipherSummary) -> bool {
    summary.counts.total > 0
        || !summary.supported_ciphers.is_empty()
        || summary.preferred_cipher.is_some()
        || !summary.server_preference.is_empty()
}

fn no_cipher_evidence_result(
    vuln_type: VulnerabilityType,
    test_name: &str,
    cve: Option<&str>,
    cwe: Option<&str>,
) -> VulnerabilityResult {
    VulnerabilityResult {
        vuln_type,
        vulnerable: false,
        inconclusive: true,
        details: format!(
            "{} test inconclusive - no successful cipher enumeration results",
            test_name
        ),
        cve: cve.map(str::to_string),
        cwe: cwe.map(str::to_string),
        severity: Severity::Info,
    }
}

/// Protocol versions probed for weak stream/NULL cipher support. These suites
/// are offered from SSL 3.0 through TLS 1.2 (TLS 1.3 dropped them entirely).
pub(crate) const WEAK_CIPHER_PROBE_PROTOCOLS: &[Protocol] =
    &[Protocol::TLS12, Protocol::TLS11, Protocol::TLS10];

/// RC4 cipher suites (wire IDs) paired with display names. Probed directly by
/// wire ID because the vendored OpenSSL build omits RC4 and the default cipher
/// enumeration deliberately excludes it, so summary-based detection never sees
/// these suites — a structural false negative for an RC4-only server.
pub(crate) const RC4_CIPHER_SUITES: &[(u16, &str)] = &[
    (0x0005, "RC4-SHA"),
    (0x0004, "RC4-MD5"),
    (0xC011, "ECDHE-RSA-RC4-SHA"),
    (0xC007, "ECDHE-ECDSA-RC4-SHA"),
    (0xC00C, "ECDH-RSA-RC4-SHA"),
    (0xC002, "ECDH-ECDSA-RC4-SHA"),
    (0xC016, "AECDH-RC4-SHA"),
    (0x0018, "ADH-RC4-MD5"),
];

/// NULL-encryption cipher suites (wire IDs) paired with display names. Probed
/// directly for the same reason as [`RC4_CIPHER_SUITES`].
pub(crate) const NULL_CIPHER_SUITES: &[(u16, &str)] = &[
    (0x0001, "NULL-MD5"),
    (0x0002, "NULL-SHA"),
    (0x003B, "NULL-SHA256"),
    (0xC006, "ECDHE-ECDSA-NULL-SHA"),
    (0xC010, "ECDHE-RSA-NULL-SHA"),
    (0xC001, "ECDH-ECDSA-NULL-SHA"),
    (0xC00B, "ECDH-RSA-NULL-SHA"),
    (0xC015, "AECDH-NULL-SHA"),
];

/// Build the RC4 verdict from a direct cipher-suite probe.
///
/// `supported` lists the RC4 suites a ServerHello confirmed; `probe_inconclusive`
/// is set when some suites could not be classified. Vulnerable when any RC4
/// suite is supported; inconclusive only when nothing was supported but a probe
/// was inconclusive (mirrors the SWEET32/FREAK probe semantics).
pub(crate) fn rc4_probe_verdict(supported: &[String], probe_inconclusive: bool) -> VulnerabilityResult {
    let vulnerable = !supported.is_empty();
    VulnerabilityResult {
        vuln_type: VulnerabilityType::RC4,
        vulnerable,
        inconclusive: !vulnerable && probe_inconclusive,
        details: if vulnerable {
            format!("Server supports RC4 ciphers: {}", supported.join(", "))
        } else if probe_inconclusive {
            "RC4 test inconclusive - could not classify one or more RC4 cipher probes".to_string()
        } else {
            "Server does not support RC4 ciphers".to_string()
        },
        cve: Some("CVE-2013-2566, CVE-2015-2808".to_string()),
        cwe: Some("CWE-326".to_string()),
        severity: if vulnerable {
            Severity::Medium
        } else {
            Severity::Info
        },
    }
}

/// Build the NULL-cipher verdict from a direct cipher-suite probe. See
/// [`rc4_probe_verdict`] for the verdict semantics.
pub(crate) fn null_probe_verdict(
    supported: &[String],
    probe_inconclusive: bool,
) -> VulnerabilityResult {
    let vulnerable = !supported.is_empty();
    VulnerabilityResult {
        vuln_type: VulnerabilityType::NullCipher,
        vulnerable,
        inconclusive: !vulnerable && probe_inconclusive,
        details: if vulnerable {
            format!(
                "Server supports NULL encryption ciphers: {}",
                supported.join(", ")
            )
        } else if probe_inconclusive {
            "NULL cipher test inconclusive - could not classify one or more NULL cipher probes"
                .to_string()
        } else {
            "Server does not support NULL ciphers".to_string()
        },
        cve: None,
        cwe: Some("CWE-327".to_string()),
        severity: if vulnerable {
            Severity::Critical
        } else {
            Severity::Info
        },
    }
}

pub(crate) fn evaluate_export<'a>(
    summaries: impl IntoIterator<Item = (Protocol, &'a ProtocolCipherSummary)>,
) -> VulnerabilityResult {
    let mut vulnerable = false;
    let mut has_cipher_evidence = false;
    let mut details = Vec::new();

    for (protocol, summary) in summaries {
        has_cipher_evidence |= summary_has_cipher_evidence(summary);
        if summary.counts.export_ciphers > 0 {
            vulnerable = true;
            details.push(format!(
                "{}: {} EXPORT cipher(s)",
                protocol, summary.counts.export_ciphers
            ));
        }
    }

    if !vulnerable && !has_cipher_evidence {
        return no_cipher_evidence_result(
            VulnerabilityType::FREAK,
            "EXPORT cipher",
            Some("CVE-2015-0204"),
            Some("CWE-327"),
        );
    }

    VulnerabilityResult {
        vuln_type: VulnerabilityType::FREAK,
        vulnerable,
        inconclusive: false,
        details: if vulnerable {
            format!(
                "Server supports EXPORT ciphers (FREAK CVE-2015-0204 / LOGJAM CVE-2015-4000): {}",
                details.join(", ")
            )
        } else {
            "Server does not support EXPORT ciphers".to_string()
        },
        cve: Some("CVE-2015-0204".to_string()),
        cwe: Some("CWE-327".to_string()),
        severity: if vulnerable {
            Severity::High
        } else {
            Severity::Info
        },
    }
}

/// Evaluate BEAST vulnerability (CVE-2011-3389)
///
/// BEAST affects both TLS 1.0 and SSL 3.0 with CBC ciphers.
/// This function evaluates both protocols for vulnerability.
pub(crate) fn evaluate_beast(
    tls10_summary: Option<&ProtocolCipherSummary>,
    ssl3_summary: Option<&ProtocolCipherSummary>,
) -> VulnerabilityResult {
    let mut vulnerable_protocols = Vec::new();

    // Check TLS 1.0
    if let Some(summary) = tls10_summary {
        let cbc_count = summary
            .supported_ciphers
            .iter()
            .filter(|c| c.encryption.contains("CBC"))
            .count();
        if cbc_count > 0 {
            vulnerable_protocols.push(format!("TLS 1.0 ({} CBC ciphers)", cbc_count));
        }
    }

    // Check SSL 3.0
    if let Some(summary) = ssl3_summary {
        let cbc_count = summary
            .supported_ciphers
            .iter()
            .filter(|c| c.encryption.contains("CBC"))
            .count();
        if cbc_count > 0 {
            vulnerable_protocols.push(format!("SSL 3.0 ({} CBC ciphers)", cbc_count));
        }
    }

    let vulnerable = !vulnerable_protocols.is_empty();

    VulnerabilityResult {
        vuln_type: VulnerabilityType::BEAST,
        vulnerable,
        inconclusive: false,
        details: if vulnerable {
            format!("Vulnerable to BEAST: {}", vulnerable_protocols.join(", "))
        } else {
            "Server does not support TLS 1.0 or SSL 3.0 with CBC ciphers".to_string()
        },
        cve: Some("CVE-2011-3389".to_string()),
        cwe: Some("CWE-326".to_string()),
        severity: if vulnerable {
            Severity::Medium
        } else {
            Severity::Info
        },
    }
}
