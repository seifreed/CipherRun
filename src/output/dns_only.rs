/// DNS-Only Output Mode - Extract and output unique domain names from certificates
///
/// This module provides functionality to extract unique domain names (including
/// Subject CN and Subject Alternative Names) from a certificate and output them
/// in a clean, deduplicated format. Wildcard domains are normalized by removing
/// the wildcard prefix.
use crate::certificates::parser::CertificateInfo;
use std::collections::HashSet;

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
            && let Some(cn) = Self::extract_cn(&cert.subject) {
                domains.insert(Self::normalize_domain(&cn));
            }

        // Add all Subject Alternative Names (SANs)
        for san in &cert.san {
            let normalized = Self::normalize_domain(san);
            domains.insert(normalized);
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
            if let Some(cn) = part.strip_prefix("CN=") {
                return Some(cn.to_string());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        // Basic normalization
        assert_eq!(DnsOnlyMode::normalize_domain("Example.COM"), "example.com");

        // With whitespace
        assert_eq!(DnsOnlyMode::normalize_domain("  example.com  "), "example.com");

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
}
