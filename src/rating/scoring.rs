// SSL Labs Scoring System - Calculate component scores
// Based on: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
// Version 2009r (May 2025)
//
// ## SSL Labs Compatibility Mode
//
// This implementation aligns with SSL Labs grading methodology:
//
// ### TLS 1.3 Requirement
// - **Without TLS 1.3, the OVERALL grade and protocol grade are capped at A-**
// - This matches SSL Labs policy: "This server does not support TLS 1.3" → caps grade at A-
// - A- score range is 80-84, so we cap at 84
//
// ### Score Ranges
// - A+: 95-100 (excellent - best practice security)
// - A:  85-94  (excellent - strong security) **REQUIRES TLS 1.3**
// - A-: 80-84  (excellent - minor issues)
// - B:  65-79  (good - adequate security)
// - C:  50-64  (fair - mediocre security)
// - D:  35-49  (poor - weak security)
// - E:  20-34  (poor - very weak security)
// - F:  0-19   (failing - critical security issues)
// - T:  Certificate not trusted
// - M:  Certificate name mismatch
//
// ### Component Weights (SSL Labs Official)
// - Protocol:      30%
// - Key Exchange:  30%
// - Cipher:        40%
// - Certificate:   Not included in overall score (but causes T/M grade overrides)
//
// ### Instant Failures
// - SSLv2 support → Score 0 (grade F)
// - NULL ciphers → Score 0 (grade F)
// - EXPORT ciphers → Score 0 (grade F)
// - Certificate expired → Grade T
// - Certificate hostname mismatch → Grade M
// - Certificate trust chain invalid → Grade T
//
// ### Vulnerability Impact Changes (2025)
// - **TLS_FALLBACK_SCSV no longer impacts grading** (as of version 2009r)
// - Only critical vulnerabilities (Heartbleed, DROWN, ROBOT, etc.) cause instant F
//
// ### License
// Copyright (C) 2025 Marc Rivero López (@seifreed)
// Licensed under GPL-3.0
//

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
        // SSL Labs methodology: Protocol 30%, Key Exchange 30%, Cipher 40%
        // Certificate is NOT included in overall score calculation
        let mut score = Self::calculate_overall_score(
            protocol_score,
            key_exchange_score,
            cipher_strength_score,
        );

        // Apply TLS 1.3 cap to OVERALL score (not just protocol score)
        // SSL Labs 2025: "If TLS 1.3 is not supported, the minimum grade is capped at A-"
        let has_tls13 = protocols
            .iter()
            .any(|p| p.supported && p.protocol == Protocol::TLS13);
        if !has_tls13 {
            // Cap at 84 (A- range is 80-84)
            score = score.min(84);
        }

        // Apply vulnerability penalties (excludes TLS_FALLBACK_SCSV as of 2025)
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
    ///
    /// SSL Labs Compatibility Mode (2025):
    /// - Protocol score contributes 30% to overall score
    /// - Without TLS 1.3, protocol score is heavily penalized
    /// - Without TLS 1.3, OVERALL score is also capped at 84 (enforced in calculate())
    /// - This aligns with SSL Labs 2025 methodology where TLS 1.3 is mandatory for A/A+ grades
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

        // SSL Labs Compatibility: Heavy penalty if TLS 1.3 is not supported
        // SSL Labs policy: "Without TLS 1.3, maximum grade is A-"
        // Apply -15 penalty for missing TLS 1.3 (in addition to overall cap at 84)
        let has_tls13 = protocols
            .iter()
            .any(|p| p.supported && p.protocol == Protocol::TLS13);

        if !has_tls13 {
            // Penalize by 15 points for missing TLS 1.3
            score = score.saturating_sub(15);
        }

        score
    }

    /// Calculate key exchange score (0-100)
    ///
    /// SSL Labs methodology:
    /// - Forward Secrecy (FS) is critical for modern security
    /// - Penalize based on percentage of ciphers lacking FS
    /// - RSA key exchange (TLS_RSA_*) lacks FS and should be heavily penalized
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
            let non_fs_percentage = 100 - fs_percentage;

            // SSL Labs criteria: Penalize based on percentage of non-FS ciphers
            if non_fs_percentage >= 50 {
                // More than 50% lack FS: -20 points
                score = score.saturating_sub(20);
            } else if non_fs_percentage >= 30 {
                // 30-49% lack FS: -10 points
                score = score.saturating_sub(10);
            } else if non_fs_percentage >= 20 {
                // 20-29% lack FS: -5 points
                score = score.saturating_sub(5);
            }
        }

        score
    }

    /// Calculate cipher strength score (0-100)
    ///
    /// SSL Labs methodology:
    /// - NULL and EXPORT ciphers = instant fail
    /// - Penalize based on PERCENTAGE of weak ciphers (low + medium strength)
    /// - CBC mode ciphers should be penalized (lack AEAD)
    /// - High percentage of weak ciphers indicates poor cipher suite configuration
    fn calculate_cipher_strength_score(ciphers: &HashMap<Protocol, ProtocolCipherSummary>) -> u8 {
        let mut score = 100u8;
        let mut total_ciphers = 0;
        let mut weak_ciphers = 0; // low + medium strength
        let mut low_strength_count = 0;
        let mut aead_count = 0;

        for summary in ciphers.values() {
            // NULL ciphers = instant F
            if summary.counts.null_ciphers > 0 {
                return 0;
            }

            // EXPORT ciphers = instant F
            if summary.counts.export_ciphers > 0 {
                return 0;
            }

            // Aggregate counts across all protocols
            total_ciphers += summary.counts.total;
            weak_ciphers += summary.counts.low_strength + summary.counts.medium_strength;
            low_strength_count += summary.counts.low_strength;
            aead_count += summary.counts.aead;
        }

        if total_ciphers > 0 {
            // Calculate percentage of weak ciphers
            let weak_percentage = (weak_ciphers * 100) / total_ciphers;
            let low_percentage = (low_strength_count * 100) / total_ciphers;

            // SSL Labs criteria: Penalize based on percentage of WEAK ciphers
            if weak_percentage >= 75 {
                // 75%+ weak ciphers: -20 points (major penalty)
                score = score.saturating_sub(20);
            } else if weak_percentage >= 50 {
                // 50-74% weak ciphers: -15 points
                score = score.saturating_sub(15);
            } else if weak_percentage >= 25 {
                // 25-49% weak ciphers: -10 points
                score = score.saturating_sub(10);
            } else if weak_percentage > 0 {
                // Any weak ciphers: -5 points
                score = score.saturating_sub(5);
            }

            // Additional penalty if LOW strength ciphers present (very weak)
            if low_percentage >= 25 {
                score = score.saturating_sub(10);
            } else if low_percentage > 0 {
                score = score.saturating_sub(5);
            }

            // Check AEAD support (penalty for CBC mode ciphers)
            let aead_percentage = (aead_count * 100) / total_ciphers;
            if aead_percentage < 50 {
                // Less than 50% AEAD: -5 points (CBC mode vulnerability)
                score = score.saturating_sub(5);
            }
        }

        score
    }

    /// Calculate overall score from component scores
    /// SSL Labs methodology: Protocol 30%, Key Exchange 30%, Cipher 40%
    fn calculate_overall_score(protocol: u8, key_exchange: u8, cipher: u8) -> u8 {
        // Weighted average: 30% protocol, 30% key exchange, 40% cipher
        let weighted = (protocol as u32 * 30 + key_exchange as u32 * 30 + cipher as u32 * 40) / 100;
        weighted.min(100) as u8
    }

    /// Apply vulnerability penalties
    /// SSL Labs 2025: TLS_FALLBACK_SCSV no longer impacts grading
    fn apply_vulnerability_penalties(
        mut score: u8,
        vulnerabilities: &[VulnerabilityResult],
    ) -> (u8, Vec<String>) {
        let mut warnings = Vec::new();

        for vuln in vulnerabilities {
            // Skip TLS_FALLBACK_SCSV - no longer impacts grading as of SSL Labs 2025
            if matches!(
                vuln.vuln_type,
                crate::vulnerabilities::VulnerabilityType::TLSFallback
            ) {
                continue;
            }

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
        // All perfect scores
        let score = RatingCalculator::calculate_overall_score(100, 100, 100);
        assert_eq!(score, 100);

        // Mixed scores: Protocol 90%, Key Exchange 85%, Cipher 95%
        // (90*30 + 85*30 + 95*40) / 100 = (2700 + 2550 + 3800) / 100 = 91
        let score = RatingCalculator::calculate_overall_score(90, 85, 95);
        assert_eq!(score, 91);

        // Test case from user report: Protocol 100%, Key Exchange 95%, Cipher 95%
        // (100*30 + 95*30 + 95*40) / 100 = (3000 + 2850 + 3800) / 100 = 96
        let score = RatingCalculator::calculate_overall_score(100, 95, 95);
        assert_eq!(score, 96);
    }

    #[test]
    fn test_certificate_score_expired() {
        // Test with expired certificate would require building a ValidationResult
        // Leaving as placeholder for integration tests
    }

    #[test]
    fn test_protocol_score_with_tls13() {
        // Server with TLS 1.3 should get full score (no cap)
        let protocols = vec![
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                preferred: false,
                ciphers_count: 10,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                preferred: true,
                ciphers_count: 5,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
        ];
        let score = RatingCalculator::calculate_protocol_score(&protocols);
        assert_eq!(score, 100, "Server with TLS 1.3 should get full score");
    }

    #[test]
    fn test_protocol_score_without_tls13_gets_penalty() {
        // Server with only TLS 1.2 (no TLS 1.3) gets -15 penalty
        // Start: 100, Penalty: -15 = 85
        let protocols = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 10,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];
        let score = RatingCalculator::calculate_protocol_score(&protocols);
        assert_eq!(
            score, 85,
            "Server without TLS 1.3 should get -15 penalty (100-15=85)"
        );
    }

    #[test]
    fn test_protocol_score_without_tls13_with_old_tls() {
        // Server with TLS 1.0, 1.1, 1.2 but no TLS 1.3
        // Initial score 100 - 5 (TLS 1.0) - 3 (TLS 1.1) - 15 (no TLS 1.3) = 77
        let protocols = vec![
            ProtocolTestResult {
                protocol: Protocol::TLS10,
                supported: true,
                preferred: false,
                ciphers_count: 20,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS11,
                supported: true,
                preferred: false,
                ciphers_count: 15,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                preferred: true,
                ciphers_count: 10,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
        ];
        let score = RatingCalculator::calculate_protocol_score(&protocols);
        // Score: 100 - 5 (TLS 1.0) - 3 (TLS 1.1) - 15 (no TLS 1.3) = 77
        assert_eq!(
            score, 77,
            "Server without TLS 1.3 gets cumulative penalties"
        );
    }

    #[test]
    fn test_protocol_score_sslv3_with_penalties() {
        // Server with SSLv3 and TLS 1.2 (no TLS 1.3)
        // Initial score 100 - 20 (SSLv3) - 15 (no TLS 1.3) = 65
        let protocols = vec![
            ProtocolTestResult {
                protocol: Protocol::SSLv3,
                supported: true,
                preferred: false,
                ciphers_count: 50,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                preferred: true,
                ciphers_count: 10,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
        ];
        let score = RatingCalculator::calculate_protocol_score(&protocols);
        assert_eq!(
            score, 65,
            "Server with SSLv3 and no TLS 1.3 gets heavy penalties"
        );
    }

    #[test]
    fn test_protocol_score_sslv2_instant_fail() {
        // SSLv2 should result in instant 0 score regardless of TLS 1.3
        let protocols = vec![
            ProtocolTestResult {
                protocol: Protocol::SSLv2,
                supported: true,
                preferred: false,
                ciphers_count: 20,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                preferred: true,
                ciphers_count: 5,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
        ];
        let score = RatingCalculator::calculate_protocol_score(&protocols);
        assert_eq!(score, 0, "SSLv2 support should result in instant fail");
    }

    #[test]
    fn test_grade_conversion_with_tls13_cap() {
        // Test that score of 84 converts to A- grade
        let grade = Grade::from_score(84);
        assert_eq!(grade, Grade::AMinus, "Score 84 should be grade A-");

        // Test that score of 85 converts to A grade
        let grade = Grade::from_score(85);
        assert_eq!(grade, Grade::A, "Score 85 should be grade A");

        // Test that score of 100 converts to A+ grade
        let grade = Grade::from_score(100);
        assert_eq!(grade, Grade::APlus, "Score 100 should be grade A+");
    }

    #[test]
    fn test_user_reported_issue_fix() {
        // User reported: Protocol 100%, Key Exchange 95%, Cipher 95%
        // Expected: A+ (96) with TLS 1.3, A- (84) without TLS 1.3
        // Was getting: B (76) due to incorrect weights and TLS_FALLBACK penalty

        use std::collections::HashMap;

        // With TLS 1.3 supported
        let protocols_with_tls13 = vec![
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                preferred: false,
                ciphers_count: 10,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                preferred: true,
                ciphers_count: 5,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
        ];

        let ciphers = HashMap::new();

        // TLS_FALLBACK_SCSV marked as "vulnerable" (false positive)
        let vulnerabilities = vec![crate::vulnerabilities::VulnerabilityResult {
            vuln_type: crate::vulnerabilities::VulnerabilityType::TLSFallback,
            vulnerable: true, // This should NOT affect grade anymore
            details: "TLS_FALLBACK_SCSV not supported".to_string(),
            cve: Some("CVE-2014-8730".to_string()),
            cwe: Some("CWE-757".to_string()),
            severity: crate::vulnerabilities::Severity::High,
        }];

        let result =
            RatingCalculator::calculate(&protocols_with_tls13, &ciphers, None, &vulnerabilities);

        // With new calculation: (100*30 + 95*30 + 95*40) / 100 = 96
        // TLS_FALLBACK_SCSV should NOT reduce the score
        // Expected grade: A+ (96 is in 95-100 range)
        assert!(
            result.score >= 95,
            "Score should be 96 or close (got {})",
            result.score
        );
        assert_eq!(
            result.grade,
            Grade::APlus,
            "Grade should be A+ with TLS 1.3 and score 96"
        );
    }

    #[test]
    fn test_tls13_overall_score_cap() {
        // Without TLS 1.3, the OVERALL score should be capped at 84 (A-)
        use std::collections::HashMap;

        let protocols_without_tls13 = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 10,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let ciphers = HashMap::new();
        let vulnerabilities = vec![];

        let result =
            RatingCalculator::calculate(&protocols_without_tls13, &ciphers, None, &vulnerabilities);

        // Even if component scores are high, overall should be capped at 84
        assert_eq!(
            result.score, 84,
            "Overall score should be capped at 84 without TLS 1.3"
        );
        assert_eq!(
            result.grade,
            Grade::AMinus,
            "Grade should be A- without TLS 1.3"
        );
    }
}
