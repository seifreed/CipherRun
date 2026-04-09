use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::Protocol;
use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

pub(crate) fn evaluate_rc4<'a>(
    summaries: impl IntoIterator<Item = (Protocol, &'a ProtocolCipherSummary)>,
) -> VulnerabilityResult {
    let mut has_rc4 = false;
    let mut details = Vec::new();

    for (protocol, summary) in summaries {
        let count = summary
            .supported_ciphers
            .iter()
            .filter(|c| c.encryption.contains("RC4"))
            .count();

        if count > 0 {
            has_rc4 = true;
            details.push(format!("{}: {} RC4 cipher(s)", protocol, count));
        }
    }

    VulnerabilityResult {
        vuln_type: VulnerabilityType::RC4,
        vulnerable: has_rc4,
        inconclusive: false,
        details: if has_rc4 {
            format!("Server supports RC4 ciphers: {}", details.join(", "))
        } else {
            "Server does not support RC4 ciphers".to_string()
        },
        cve: Some("CVE-2013-2566, CVE-2015-2808".to_string()),
        cwe: Some("CWE-326".to_string()),
        severity: if has_rc4 {
            Severity::Medium
        } else {
            Severity::Info
        },
    }
}

pub(crate) fn evaluate_3des<'a>(
    summaries: impl IntoIterator<Item = (Protocol, &'a ProtocolCipherSummary)>,
) -> VulnerabilityResult {
    let mut vulnerable = false;
    let mut details = Vec::new();

    for (protocol, summary) in summaries {
        let count = summary
            .supported_ciphers
            .iter()
            .filter(|c| c.encryption.contains("3DES") || c.encryption.contains("DES"))
            .count();

        if count > 0 {
            vulnerable = true;
            details.push(format!("{}: {} 3DES/DES cipher(s)", protocol, count));
        }
    }

    VulnerabilityResult {
        vuln_type: VulnerabilityType::SWEET32,
        vulnerable,
        inconclusive: false,
        details: if vulnerable {
            format!(
                "Server supports 3DES/DES ciphers (SWEET32): {}",
                details.join(", ")
            )
        } else {
            "Server does not support 3DES/DES ciphers".to_string()
        },
        cve: Some("CVE-2016-2183".to_string()),
        cwe: Some("CWE-327".to_string()),
        severity: if vulnerable {
            Severity::Medium
        } else {
            Severity::Info
        },
    }
}

pub(crate) fn evaluate_null<'a>(
    summaries: impl IntoIterator<Item = (Protocol, &'a ProtocolCipherSummary)>,
) -> VulnerabilityResult {
    let mut vulnerable = false;
    let mut details = Vec::new();

    for (protocol, summary) in summaries {
        if summary.counts.null_ciphers > 0 {
            vulnerable = true;
            details.push(format!(
                "{}: {} NULL cipher(s)",
                protocol, summary.counts.null_ciphers
            ));
        }
    }

    VulnerabilityResult {
        vuln_type: VulnerabilityType::NullCipher,
        vulnerable,
        inconclusive: false,
        details: if vulnerable {
            format!(
                "Server supports NULL encryption ciphers: {}",
                details.join(", ")
            )
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
    let mut details = Vec::new();

    for (protocol, summary) in summaries {
        if summary.counts.export_ciphers > 0 {
            vulnerable = true;
            details.push(format!(
                "{}: {} EXPORT cipher(s)",
                protocol, summary.counts.export_ciphers
            ));
        }
    }

    VulnerabilityResult {
        vuln_type: VulnerabilityType::FREAK,
        vulnerable,
        inconclusive: false,
        details: if vulnerable {
            format!(
                "Server supports EXPORT ciphers (FREAK/LOGJAM): {}",
                details.join(", ")
            )
        } else {
            "Server does not support EXPORT ciphers".to_string()
        },
        cve: Some("CVE-2015-0204, CVE-2015-4000".to_string()),
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
