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

        // SSLv2 support → unconditional grade F (protocol_score is forced to 0 by SSLv2).
        // The weighted average cannot enforce this: (0×30 + 100×30 + 100×40)/100 = 70 = B.
        if protocol_score == 0 {
            return RatingResult {
                grade: Grade::F,
                score: 0,
                certificate_score,
                protocol_score,
                key_exchange_score,
                cipher_strength_score,
                warnings: vec!["SSLv2 supported — unconditional grade F".to_string()],
            };
        }

        // NULL or EXPORT ciphers → unconditional grade F regardless of other scores.
        // The weighted average cannot enforce this guarantee (e.g. 100/100/0 → 60 = C).
        if cipher_strength_score == 0 {
            return RatingResult {
                grade: Grade::F,
                score: 0,
                certificate_score,
                protocol_score,
                key_exchange_score,
                cipher_strength_score,
                warnings: vec![
                    "NULL or EXPORT ciphers supported — unconditional grade F".to_string(),
                ],
            };
        }

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
            score = score.min(Grade::AMinus.max_score());
        }

        // SSL Labs deprecated-protocol grade caps (version 2009q, 2020):
        // supporting SSL 3.0 caps the grade at C; supporting TLS 1.0 or TLS 1.1
        // caps it at B. These are hard caps on the overall score, independent of
        // the weighted component average — a strong cipher/key-exchange
        // configuration cannot lift a server that still offers deprecated
        // protocols above the capped grade. The lowest applicable cap wins via
        // `min`, so a server offering both SSL 3.0 and TLS 1.0 is capped at C.
        let supports =
            |proto: Protocol| protocols.iter().any(|p| p.supported && p.protocol == proto);
        if supports(Protocol::SSLv3) {
            score = score.min(Grade::C.max_score());
        }
        if supports(Protocol::TLS10) || supports(Protocol::TLS11) {
            score = score.min(Grade::B.max_score());
        }

        // Apply vulnerability penalties (excludes TLS_FALLBACK_SCSV as of 2025)
        let (score_after_vulns, warnings) =
            Self::apply_vulnerability_penalties(score, vulnerabilities);
        let mut score = score_after_vulns;

        // Determine grade
        let mut grade = Grade::from_score(score);

        // Check for certificate issues that override grade.
        // Priority: expired/untrusted (Grade T) takes precedence over mismatch (Grade M),
        // because an expired cert is a more severe trust failure.
        // Score is also zeroed to avoid contradictory { grade: T, score: 96 } output.
        if let Some(cert) = certificate {
            if !cert.not_expired {
                grade = Grade::T; // Certificate expired — most critical
                score = 0;
            } else if !cert.trust_chain_valid {
                grade = Grade::T; // Trust chain invalid
                score = 0;
            } else if !cert.hostname_match {
                grade = Grade::M; // Certificate name mismatch
                score = 0;
            }
        }
        // Note: certificate=None means cert evaluation was skipped (e.g. protocol-only scan).
        // On a full TLS scan a certificate phase that retrieved no certificate is graded
        // Grade::Unverified upstream (see Scanner::calculate_rating) — distinct from the
        // Grade::T set above, which means a certificate WAS retrieved and is not trusted.

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
    /// - Without TLS 1.3, OVERALL score is capped at 84 (enforced in calculate())
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
        let mut total_ciphers = 0usize;
        let mut fs_ciphers = 0usize;

        for summary in ciphers.values() {
            total_ciphers = total_ciphers.saturating_add(summary.counts.total);
            fs_ciphers = fs_ciphers.saturating_add(summary.counts.forward_secrecy);
        }

        if let Some(fs_percentage) = percentage(fs_ciphers, total_ciphers) {
            let non_fs_percentage = 100usize.saturating_sub(fs_percentage);

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
        let mut total_ciphers = 0usize;
        let mut weak_ciphers = 0usize; // low + medium strength (matches weak_percentage doc)
        let mut aead_count = 0usize;

        for summary in ciphers.values() {
            // NULL ciphers = instant F
            if summary.counts.null_ciphers > 0 {
                return 0;
            }

            // EXPORT ciphers = instant F
            if summary.counts.export_ciphers > 0 {
                return 0;
            }

            // Aggregate counts across all protocols. Weak = low + medium strength,
            // matching the documented weak_percentage definition and the policy
            // module (policy/rules/cipher.rs), which classify both as weak.
            total_ciphers = total_ciphers.saturating_add(summary.counts.total);
            weak_ciphers = weak_ciphers.saturating_add(
                summary
                    .counts
                    .low_strength
                    .saturating_add(summary.counts.medium_strength),
            );
            aead_count = aead_count.saturating_add(summary.counts.aead);
        }

        if let Some(weak_percentage) = percentage(weak_ciphers, total_ciphers) {
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

            // Note: low-strength ciphers are already penalized as part of weak_percentage
            // (which includes low + medium strength). No separate penalty needed.

            // Check AEAD support (penalty for CBC mode ciphers).
            // Guaranteed `Some` here: total_ciphers is non-zero inside this block.
            let aead_percentage = percentage(aead_count, total_ciphers).unwrap_or(0);
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

            // Only confirmed vulnerabilities affect the grade. An inconclusive
            // finding (e.g. a remote timing oracle the scanner could not confirm)
            // is surfaced in the report's vulnerability section but must not tank
            // the grade on unconfirmed evidence: doing so contradicts its
            // "Inconclusive" status and re-introduces the timing-jitter false
            // positives the detectors deliberately downgrade to inconclusive.
            if vuln.inconclusive {
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

fn percentage(numerator: usize, denominator: usize) -> Option<usize> {
    if denominator == 0 {
        return None;
    }

    let percentage = (numerator as u128)
        .saturating_mul(100)
        .checked_div(denominator as u128)?;
    Some(usize::try_from(percentage.min(100)).expect("percentage is capped at 100"))
}

#[cfg(test)]
#[path = "scoring_tests.rs"]
mod tests;
