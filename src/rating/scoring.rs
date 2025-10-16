// SSL Labs Scoring System - Calculate component scores
// Based on: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide

use crate::certificates::validator::ValidationResult;
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::vulnerabilities::VulnerabilityResult;
use std::collections::HashMap;

use super::grader::Grade;
use serde::{Deserialize, Serialize};

/// Rating result with detailed scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingResult {
    pub grade: Grade,
    pub score: u8, // 0-100
    pub certificate_score: u8,
    pub protocol_score: u8,
    pub key_exchange_score: u8,
    pub cipher_strength_score: u8,
    pub warnings: Vec<String>,
}

/// SSL Labs rating calculator
pub struct RatingCalculator;

impl RatingCalculator {
    /// Calculate overall rating
    pub fn calculate(
        protocols: &[ProtocolTestResult],
        ciphers: &HashMap<Protocol, ProtocolCipherSummary>,
        certificate: Option<&ValidationResult>,
        vulnerabilities: &[VulnerabilityResult],
    ) -> RatingResult {
        // Calculate individual scores
        let certificate_score = Self::calculate_certificate_score(certificate);
        let protocol_score = Self::calculate_protocol_score(protocols);
        let key_exchange_score = Self::calculate_key_exchange_score(ciphers);
        let cipher_strength_score = Self::calculate_cipher_strength_score(ciphers);

        // Calculate overall score (weighted average)
        let score = Self::calculate_overall_score(
            certificate_score,
            protocol_score,
            key_exchange_score,
            cipher_strength_score,
        );

        // Apply vulnerability penalties
        let (score, warnings) = Self::apply_vulnerability_penalties(score, vulnerabilities);

        // Determine grade
        let mut grade = Grade::from_score(score);

        // Check for certificate issues that override grade
        if let Some(cert) = certificate {
            if !cert.hostname_match {
                grade = Grade::M; // Certificate name mismatch
            } else if !cert.trust_chain_valid {
                grade = Grade::T; // Trust issues
            }
        }

        RatingResult {
            grade,
            score,
            certificate_score,
            protocol_score,
            key_exchange_score,
            cipher_strength_score,
            warnings,
        }
    }

    /// Calculate certificate score (0-100)
    fn calculate_certificate_score(certificate: Option<&ValidationResult>) -> u8 {
        let Some(cert) = certificate else {
            return 0;
        };

        let mut score = 100u8;

        // Expired certificate
        if !cert.not_expired {
            return 0;
        }

        // Invalid hostname
        if !cert.hostname_match {
            return 0;
        }

        // Trust chain invalid
        if !cert.trust_chain_valid {
            return 0;
        }

        // Deduct points for issues
        use crate::certificates::validator::IssueSeverity;
        for issue in &cert.issues {
            let deduction = match issue.severity {
                IssueSeverity::Critical => 40,
                IssueSeverity::High => 20,
                IssueSeverity::Medium => 10,
                IssueSeverity::Low => 5,
                IssueSeverity::Info => 0,
            };
            score = score.saturating_sub(deduction);
        }

        score
    }

    /// Calculate protocol support score (0-100)
    fn calculate_protocol_score(protocols: &[ProtocolTestResult]) -> u8 {
        let mut score = 100u8;

        for result in protocols {
            if result.supported {
                match result.protocol {
                    Protocol::SSLv2 => score = 0, // SSLv2 = instant F
                    Protocol::SSLv3 => score = score.saturating_sub(20), // SSLv3 = major penalty
                    Protocol::TLS10 => score = score.saturating_sub(5), // TLS 1.0 = minor penalty
                    Protocol::TLS11 => score = score.saturating_sub(3), // TLS 1.1 = minor penalty
                    Protocol::TLS12 | Protocol::TLS13 => {} // Good
                    Protocol::QUIC => {}          // QUIC is good (based on TLS 1.3)
                }
            }
        }

        // Check if TLS 1.2 or 1.3 is supported
        let has_modern_tls = protocols.iter().any(|p| {
            p.supported && (p.protocol == Protocol::TLS12 || p.protocol == Protocol::TLS13)
        });

        if !has_modern_tls {
            score = score.saturating_sub(20);
        }

        score
    }

    /// Calculate key exchange score (0-100)
    fn calculate_key_exchange_score(ciphers: &HashMap<Protocol, ProtocolCipherSummary>) -> u8 {
        let mut score = 100u8;

        // Check forward secrecy support
        let mut total_ciphers = 0;
        let mut fs_ciphers = 0;

        for summary in ciphers.values() {
            total_ciphers += summary.counts.total;
            fs_ciphers += summary.counts.forward_secrecy;
        }

        if total_ciphers > 0 {
            let fs_percentage = (fs_ciphers * 100) / total_ciphers;
            if fs_percentage < 30 {
                score = score.saturating_sub(20);
            } else if fs_percentage < 50 {
                score = score.saturating_sub(10);
            } else if fs_percentage < 80 {
                score = score.saturating_sub(5);
            }
        }

        score
    }

    /// Calculate cipher strength score (0-100)
    fn calculate_cipher_strength_score(ciphers: &HashMap<Protocol, ProtocolCipherSummary>) -> u8 {
        let mut score = 100u8;

        for summary in ciphers.values() {
            // NULL ciphers = instant F
            if summary.counts.null_ciphers > 0 {
                return 0;
            }

            // EXPORT ciphers = instant F
            if summary.counts.export_ciphers > 0 {
                return 0;
            }

            // Low strength ciphers
            if summary.counts.low_strength > 0 {
                score = score.saturating_sub(20);
            }

            // Medium strength ciphers
            if summary.counts.medium_strength > 0 && summary.counts.high_strength == 0 {
                score = score.saturating_sub(10);
            }

            // Check AEAD support
            if summary.counts.total > 0 {
                let aead_percentage = (summary.counts.aead * 100) / summary.counts.total;
                if aead_percentage < 50 {
                    score = score.saturating_sub(5);
                }
            }
        }

        score
    }

    /// Calculate overall score from component scores
    fn calculate_overall_score(cert: u8, protocol: u8, key_exchange: u8, cipher: u8) -> u8 {
        // Weighted average: 30% cert, 30% protocol, 20% key exchange, 20% cipher
        let weighted = (cert as u32 * 30
            + protocol as u32 * 30
            + key_exchange as u32 * 20
            + cipher as u32 * 20)
            / 100;
        weighted.min(100) as u8
    }

    /// Apply vulnerability penalties
    fn apply_vulnerability_penalties(
        mut score: u8,
        vulnerabilities: &[VulnerabilityResult],
    ) -> (u8, Vec<String>) {
        let mut warnings = Vec::new();

        for vuln in vulnerabilities {
            if vuln.vulnerable {
                use crate::vulnerabilities::Severity;
                let (deduction, warning) = match vuln.severity {
                    Severity::Critical => {
                        (40, format!("Critical vulnerability: {:?}", vuln.vuln_type))
                    }
                    Severity::High => (
                        20,
                        format!("High severity vulnerability: {:?}", vuln.vuln_type),
                    ),
                    Severity::Medium => (
                        10,
                        format!("Medium severity vulnerability: {:?}", vuln.vuln_type),
                    ),
                    Severity::Low => (
                        5,
                        format!("Low severity vulnerability: {:?}", vuln.vuln_type),
                    ),
                    Severity::Info => (0, String::new()),
                };

                score = score.saturating_sub(deduction);
                if !warning.is_empty() {
                    warnings.push(warning);
                }
            }
        }

        (score, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overall_score_calculation() {
        let score = RatingCalculator::calculate_overall_score(100, 100, 100, 100);
        assert_eq!(score, 100);

        let score = RatingCalculator::calculate_overall_score(80, 90, 85, 95);
        assert_eq!(score, 87); // (80*30 + 90*30 + 85*20 + 95*20) / 100
    }

    #[test]
    fn test_certificate_score_expired() {
        // Test with expired certificate would require building a ValidationResult
        // Leaving as placeholder for integration tests
    }
}
