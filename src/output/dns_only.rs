/// DNS-Only Output Mode - Extract and output unique domain names from certificates
///
/// This module provides functionality to extract unique domain names (including
/// Subject CN and Subject Alternative Names) from a certificate and output them
/// in a clean, deduplicated format. Wildcard domains are normalized by removing
/// the wildcard prefix.
use crate::certificates::parser::CertificateInfo;
use crate::scanner::ScanResults;
use std::collections::HashSet;
use std::net::IpAddr;

/// DNS-Only output mode
pub struct DnsOnlyMode;

impl DnsOnlyMode {
    /// Extract unique domains from certificate, deduplicating and normalizing
    ///
    /// # Arguments
    /// * `cert` - The certificate to extract domains from
    ///
    /// # Returns
    /// A sorted vector of unique, normalized domain names
    ///
    /// # Examples
    /// ```ignore
    /// let domains = DnsOnlyMode::extract_domains(&cert);
    /// // domains: ["api.example.com", "example.com", "www.example.com"]
    /// ```
    pub fn extract_domains(cert: &CertificateInfo) -> Vec<String> {
        let mut domains = HashSet::new();

        // Extract the Common Name (CN) from the subject
        // Format is typically "CN=example.com" or similar
        if !cert.subject.is_empty()
            && let Some(cn) = Self::extract_cn(&cert.subject)
            && let Some(domain) = Self::normalize_dns_domain(&cn)
        {
            domains.insert(domain);
        }

        // Add all Subject Alternative Names (SANs)
        for san in &cert.san {
            if let Some(domain) = Self::normalize_dns_domain(san) {
                domains.insert(domain);
            }
        }

        // Convert to sorted vector
        let mut result: Vec<String> = domains.into_iter().collect();
        result.sort();

        result
    }

    /// Extract the Common Name (CN) from an X.509 subject string
    ///
    /// The subject string typically looks like:
    /// "CN=example.com,O=Organization,C=US"
    /// or
    /// "C=US, O=Organization, CN=example.com"
    fn extract_cn(subject: &str) -> Option<String> {
        for part in subject.split(',') {
            let part = part.trim();
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            if key.trim().eq_ignore_ascii_case("CN") {
                return Some(value.trim().to_string());
            }
        }
        None
    }

    /// Normalize a domain name for consistent output
    ///
    /// Performs the following normalizations:
    /// 1. Convert to lowercase
    /// 2. Trim whitespace
    /// 3. Remove leading "DNS:" prefix (used in SAN lists)
    /// 4. Remove wildcard prefix ("*.") if present
    fn normalize_domain(domain: &str) -> String {
        let mut normalized = domain.to_lowercase().trim().to_string();

        // Remove "DNS:" prefix if present (from SAN parsing)
        if normalized.starts_with("dns:") {
            normalized = normalized[4..].to_string();
        }

        // Remove wildcard prefix
        if normalized.starts_with("*.") {
            normalized = normalized[2..].to_string();
        }

        normalized.trim().to_string()
    }

    /// Normalize and filter a value so only DNS-style names remain.
    fn normalize_dns_domain(domain: &str) -> Option<String> {
        let normalized = Self::normalize_domain(domain);
        if normalized.is_empty() {
            return None;
        }

        if normalized.starts_with("ip:") {
            return None;
        }

        if normalized.parse::<IpAddr>().is_ok() {
            return None;
        }

        Some(normalized)
    }

    /// Extract unique domains from a certificate chain
    ///
    /// This processes only the leaf certificate (first in chain).
    /// Intermediate and root certificates are typically not relevant for
    /// domain enumeration.
    ///
    /// # Arguments
    /// * `leaf_cert` - The leaf certificate (typically the first certificate in a chain)
    ///
    /// # Returns
    /// A formatted string with one domain per line
    pub fn format_output(leaf_cert: &CertificateInfo) -> String {
        let domains = Self::extract_domains(leaf_cert);

        if domains.is_empty() {
            String::new()
        } else {
            domains.join("\n")
        }
    }

    /// Extract DNS-only output from a full scan result.
    pub fn format_scan_results(results: &ScanResults) -> String {
        results
            .certificate_chain
            .as_ref()
            .and_then(|analysis| analysis.chain.leaf())
            .map(Self::format_output)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        // Basic normalization
        assert_eq!(DnsOnlyMode::normalize_domain("Example.COM"), "example.com");

        // With whitespace
        assert_eq!(
            DnsOnlyMode::normalize_domain("  example.com  "),
            "example.com"
        );

        // Wildcard removal
        assert_eq!(
            DnsOnlyMode::normalize_domain("*.example.com"),
            "example.com"
        );

        // Wildcard with case
        assert_eq!(
            DnsOnlyMode::normalize_domain("*.EXAMPLE.COM"),
            "example.com"
        );

        // DNS prefix removal
        assert_eq!(
            DnsOnlyMode::normalize_domain("DNS:example.com"),
            "example.com"
        );

        // Complex case
        assert_eq!(
            DnsOnlyMode::normalize_domain("DNS:*.EXAMPLE.COM  "),
            "example.com"
        );
    }

    #[test]
    fn test_extract_cn() {
        // Standard format
        assert_eq!(
            DnsOnlyMode::extract_cn("CN=example.com,O=Org,C=US"),
            Some("example.com".to_string())
        );

        // With spaces
        assert_eq!(
            DnsOnlyMode::extract_cn("C=US, O=Org, CN=example.com"),
            Some("example.com".to_string())
        );

        // No CN
        assert_eq!(DnsOnlyMode::extract_cn("O=Org,C=US"), None);

        // CN at end
        assert_eq!(
            DnsOnlyMode::extract_cn("C=US,CN=example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_cn_allows_spaces_around_equals_and_lowercase_key() {
        assert_eq!(
            DnsOnlyMode::extract_cn("C=US, O=Org, CN = spaced.example.com"),
            Some("spaced.example.com".to_string())
        );
        assert_eq!(
            DnsOnlyMode::extract_cn("c=us, o=org, cn=lower.example.com"),
            Some("lower.example.com".to_string())
        );
    }

    #[test]
    fn test_format_output_empty_when_no_domains() {
        let cert = CertificateInfo::default();
        let output = DnsOnlyMode::format_output(&cert);
        assert!(output.is_empty());
    }

    #[test]
    fn test_extract_domains_dedup_and_normalize() {
        let cert = CertificateInfo {
            subject: "CN=Example.com,O=Org,C=US".to_string(),
            san: vec![
                "DNS:*.example.com".to_string(),
                "www.example.com".to_string(),
                "EXAMPLE.com".to_string(),
            ],
            ..Default::default()
        };

        let mut domains = DnsOnlyMode::extract_domains(&cert);
        domains.sort();
        assert_eq!(
            domains,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn test_extract_domains_skips_ip_sans_and_ip_cn() {
        let cert = CertificateInfo {
            subject: "CN=192.0.2.1,O=Org,C=US".to_string(),
            san: vec![
                "192.0.2.1".to_string(),
                "2001:db8::1".to_string(),
                "IP:0a000001".to_string(),
                "DNS:example.com".to_string(),
            ],
            ..Default::default()
        };

        let domains = DnsOnlyMode::extract_domains(&cert);

        assert_eq!(domains, vec!["example.com".to_string()]);
    }

    #[test]
    fn test_format_output_multiple_domains() {
        let cert = CertificateInfo {
            subject: "CN=api.example.com,O=Org,C=US".to_string(),
            san: vec!["www.example.com".to_string()],
            ..Default::default()
        };

        let output = DnsOnlyMode::format_output(&cert);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&"api.example.com"));
        assert!(lines.contains(&"www.example.com"));
    }

    #[test]
    fn test_extract_domains_from_san_only() {
        let cert = CertificateInfo {
            subject: "".to_string(),
            san: vec!["DNS:EXAMPLE.COM".to_string()],
            ..Default::default()
        };

        let domains = DnsOnlyMode::extract_domains(&cert);
        assert_eq!(domains, vec!["example.com".to_string()]);
    }

    #[test]
    fn test_extract_domains_sorted_output() {
        let cert = CertificateInfo {
            subject: "CN=c.example.com,O=Org".to_string(),
            san: vec!["b.example.com".to_string(), "a.example.com".to_string()],
            ..Default::default()
        };

        let domains = DnsOnlyMode::extract_domains(&cert);
        assert_eq!(
            domains,
            vec![
                "a.example.com".to_string(),
                "b.example.com".to_string(),
                "c.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn test_format_output_empty_when_no_domains_returns_empty() {
        let cert = CertificateInfo::default();
        let output = DnsOnlyMode::format_output(&cert);
        assert!(output.is_empty());
    }

    #[test]
    fn test_format_scan_results_uses_leaf_certificate() {
        let leaf = CertificateInfo {
            subject: "CN=api.example.com".to_string(),
            san: vec!["www.example.com".to_string()],
            ..Default::default()
        };

        let chain = crate::certificates::parser::CertificateChain {
            certificates: vec![leaf],
            chain_length: 1,
            chain_size_bytes: 1,
        };

        let results = crate::scanner::ScanResults {
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain,
                validation: crate::certificates::validator::ValidationResult {
                    valid: true,
                    issues: Vec::new(),
                    trust_chain_valid: true,
                    hostname_match: true,
                    not_expired: true,
                    signature_valid: true,
                    trusted_ca: None,
                    platform_trust: None,
                },
                revocation: None,
            }),
            ..Default::default()
        };

        let output = DnsOnlyMode::format_scan_results(&results);
        assert!(output.contains("api.example.com"));
        assert!(output.contains("www.example.com"));
    }
}
