use super::*;

#[test]
fn test_overall_score_calculation() {
    // All perfect scores
    let score = RatingCalculator::calculate_overall_score(100, 100, 100);
    assert_eq!(score, 100);

    // Mixed scores: Protocol 90%, Key Exchange 85%, Cipher 95%
    // (90*30 + 85*30 + 95*40) / 100 = (2700 + 2550 + 3800) / 100 = 90
    let score = RatingCalculator::calculate_overall_score(90, 85, 95);
    assert_eq!(score, 90);

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
            inconclusive: false,
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
            inconclusive: false,
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
    // Server with only TLS 1.2 (no TLS 1.3): no penalty in protocol_score.
    // The A- cap is enforced at the overall score level in calculate().
    let protocols = vec![ProtocolTestResult {
        protocol: Protocol::TLS12,
        supported: true,
        inconclusive: false,
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
        score, 100,
        "Server without TLS 1.3 should get no penalty in protocol score (cap is applied at overall level)"
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
            inconclusive: false,
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
            inconclusive: false,
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
            inconclusive: false,
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
    // Score: 100 - 5 (TLS 1.0) - 3 (TLS 1.1) = 92 (no TLS 1.3 cap applied at overall level)
    assert_eq!(
        score, 92,
        "Server without TLS 1.3 gets cumulative protocol penalties (TLS 1.0 and 1.1 only)"
    );
}

#[test]
fn test_protocol_score_sslv3_with_penalties() {
    // Server with SSLv3 and TLS 1.2 (no TLS 1.3)
    // Initial score 100 - 20 (SSLv3) = 80 (no TLS 1.3 cap applied at overall level)
    let protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::SSLv3,
            supported: true,
            inconclusive: false,
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
            inconclusive: false,
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
        score, 80,
        "Server with SSLv3 and no TLS 1.3 gets SSLv3 penalty only (TLS 1.3 cap at overall level)"
    );
}

#[test]
fn test_protocol_score_sslv2_instant_fail() {
    // SSLv2 should result in instant 0 score regardless of TLS 1.3
    let protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::SSLv2,
            supported: true,
            inconclusive: false,
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
            inconclusive: false,
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
fn test_sslv2_forces_grade_f_in_calculate() {
    // SSLv2 support must produce Grade F even when cipher/key-exchange scores are high.
    // Before fix: (0×30 + 100×30 + 100×40)/100 = 70 → Grade B (wrong).
    // After fix: protocol_score==0 triggers early-return with Grade F.
    use std::collections::HashMap;

    let protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::SSLv2,
            supported: true,
            inconclusive: false,
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
            inconclusive: false,
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
    let result = RatingCalculator::calculate(&protocols, &ciphers, None, &[]);
    assert_eq!(result.grade, Grade::F, "SSLv2 must produce Grade F");
    assert_eq!(result.score, 0, "SSLv2 must produce score 0");
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
            inconclusive: false,
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
            inconclusive: false,
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
        inconclusive: false,
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
        inconclusive: false,
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

#[test]
fn test_certificate_score_with_issues() {
    use crate::certificates::validator::{IssueSeverity, IssueType, ValidationIssue};

    let cert = ValidationResult {
        valid: true,
        issues: vec![
            ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::SelfSigned,
                description: "self-signed".to_string(),
            },
            ValidationIssue {
                severity: IssueSeverity::Low,
                issue_type: IssueType::MissingExtension,
                description: "missing ext".to_string(),
            },
        ],
        trust_chain_valid: true,
        hostname_match: true,
        not_expired: true,
        signature_valid: true,
        trusted_ca: None,
        platform_trust: None,
    };

    let score = RatingCalculator::calculate_certificate_score(Some(&cert));
    assert_eq!(score, 55);
}

#[test]
fn test_key_exchange_score_penalty_for_low_fs() {
    use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
    use std::collections::HashMap;

    let summary = ProtocolCipherSummary {
        protocol: Protocol::TLS12,
        supported_ciphers: Vec::new(),
        server_ordered: false,
        server_preference: Vec::new(),
        preferred_cipher: None,
        counts: CipherCounts {
            total: 10,
            forward_secrecy: 4,
            ..Default::default()
        },
        avg_handshake_time_ms: None,
    };

    let mut ciphers = HashMap::new();
    ciphers.insert(Protocol::TLS12, summary);

    let score = RatingCalculator::calculate_key_exchange_score(&ciphers);
    assert_eq!(score, 80);
}

#[test]
fn test_cipher_strength_score_export_ciphers_zero() {
    use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
    use std::collections::HashMap;

    let summary = ProtocolCipherSummary {
        protocol: Protocol::TLS12,
        supported_ciphers: Vec::new(),
        server_ordered: false,
        server_preference: Vec::new(),
        preferred_cipher: None,
        counts: CipherCounts {
            total: 1,
            export_ciphers: 1,
            ..Default::default()
        },
        avg_handshake_time_ms: None,
    };

    let mut ciphers = HashMap::new();
    ciphers.insert(Protocol::TLS12, summary);

    let score = RatingCalculator::calculate_cipher_strength_score(&ciphers);
    assert_eq!(score, 0);
}

#[test]
fn test_cipher_strength_score_counts_medium_strength_as_weak() {
    use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
    use std::collections::HashMap;

    // All ciphers medium-strength: weak_percentage is 100%, which must incur the
    // 75%+ weak penalty (-20) plus the <50% AEAD penalty (-5) -> 75.
    let summary = ProtocolCipherSummary {
        protocol: Protocol::TLS12,
        supported_ciphers: Vec::new(),
        server_ordered: false,
        server_preference: Vec::new(),
        preferred_cipher: None,
        counts: CipherCounts {
            total: 4,
            medium_strength: 4,
            ..Default::default()
        },
        avg_handshake_time_ms: None,
    };

    let mut ciphers = HashMap::new();
    ciphers.insert(Protocol::TLS12, summary);

    let score = RatingCalculator::calculate_cipher_strength_score(&ciphers);
    assert!(
        score < 100,
        "medium-strength ciphers must reduce the cipher-strength score, got {score}"
    );
    assert_eq!(score, 75);
}

/// Build a supported `ProtocolTestResult` for the given protocol.
#[cfg(test)]
fn supported_protocol(protocol: Protocol) -> ProtocolTestResult {
    ProtocolTestResult {
        protocol,
        supported: true,
        inconclusive: false,
        preferred: false,
        ciphers_count: 0,
        handshake_time_ms: None,
        heartbeat_enabled: None,
        session_resumption_caching: None,
        session_resumption_tickets: None,
        secure_renegotiation: None,
    }
}

#[test]
fn test_tls10_support_caps_grade_at_b() {
    use std::collections::HashMap;

    // Strong modern config (TLS 1.2 + 1.3) that would otherwise score A/A+,
    // but TLS 1.0 is still enabled, so SSL Labs caps the grade at B.
    let protocols = vec![
        supported_protocol(Protocol::TLS10),
        supported_protocol(Protocol::TLS12),
        supported_protocol(Protocol::TLS13),
    ];
    let ciphers = HashMap::new();

    let result = RatingCalculator::calculate(&protocols, &ciphers, None, &[]);

    assert_eq!(
        result.grade,
        Grade::B,
        "TLS 1.0 support must cap the grade at B, got {} (score {})",
        result.grade,
        result.score
    );
    assert!(result.score <= Grade::B.max_score());
}

#[test]
fn test_tls11_support_caps_grade_at_b() {
    use std::collections::HashMap;

    let protocols = vec![
        supported_protocol(Protocol::TLS11),
        supported_protocol(Protocol::TLS12),
        supported_protocol(Protocol::TLS13),
    ];
    let ciphers = HashMap::new();

    let result = RatingCalculator::calculate(&protocols, &ciphers, None, &[]);

    assert_eq!(
        result.grade,
        Grade::B,
        "TLS 1.1 support must cap the grade at B"
    );
}

#[test]
fn test_sslv3_support_caps_grade_at_c() {
    use std::collections::HashMap;

    // SSL 3.0 is worse than TLS 1.0: the lower C cap must win even though TLS
    // 1.0 is also offered.
    let protocols = vec![
        supported_protocol(Protocol::SSLv3),
        supported_protocol(Protocol::TLS10),
        supported_protocol(Protocol::TLS12),
        supported_protocol(Protocol::TLS13),
    ];
    let ciphers = HashMap::new();

    let result = RatingCalculator::calculate(&protocols, &ciphers, None, &[]);

    assert_eq!(
        result.grade,
        Grade::C,
        "SSL 3.0 support must cap the grade at C, got {}",
        result.grade
    );
}

#[test]
fn test_modern_protocols_not_capped_by_legacy_rule() {
    use std::collections::HashMap;

    // No deprecated protocols: the legacy caps must not apply.
    let protocols = vec![
        supported_protocol(Protocol::TLS12),
        supported_protocol(Protocol::TLS13),
    ];
    let ciphers = HashMap::new();

    let result = RatingCalculator::calculate(&protocols, &ciphers, None, &[]);

    assert!(
        result.grade >= Grade::A,
        "A TLS 1.2 + 1.3 server must not be capped by the legacy-protocol rule, got {}",
        result.grade
    );
}
