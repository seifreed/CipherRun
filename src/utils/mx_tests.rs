use super::*;
use crate::error::TlsError;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::rating::grader::Grade;
use crate::rating::scoring::RatingResult;
use crate::scanner::{RatingResults, ScanResults};

#[test]
fn test_mx_record_creation() {
    let mx = MxRecord {
        priority: 10,
        hostname: "mx.example.com".to_string(),
    };

    assert_eq!(mx.priority, 10);
    assert_eq!(mx.hostname, "mx.example.com");
}

#[test]
fn test_parse_dig_output() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"10 mx1.example.com.\n20 mx2.example.com.\n";

    let records = tester
        .parse_dig_output(output)
        .expect("test assertion should succeed");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].priority, 10);
    assert_eq!(records[0].hostname, "mx1.example.com");
}

#[test]
fn test_parse_nslookup_output() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"example.com\tmail exchanger = 5 mx1.example.com.\nexample.com\tmail exchanger = 10 mx2.example.com.\n";

    let records = tester
        .parse_nslookup_output(output)
        .expect("test assertion should succeed");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].priority, 5);
    assert_eq!(records[0].hostname, "mx1.example.com");
}

#[test]
fn test_parse_nslookup_output_is_case_insensitive() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"example.com\tMAIL EXCHANGER = 15 MX.EXAMPLE.COM.\n";

    let records = tester
        .parse_nslookup_output(output)
        .expect("test assertion should succeed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].priority, 15);
    assert_eq!(records[0].hostname, "MX.EXAMPLE.COM");
}

#[test]
fn test_parse_dig_output_handles_whitespace() {
    let tester = MxTester::new("example.com".to_string());
    let output = b" 10   mx1.example.com. \n\n  30\tmx3.example.com.\n";

    let records = tester
        .parse_dig_output(output)
        .expect("test assertion should succeed");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].priority, 10);
    assert_eq!(records[0].hostname, "mx1.example.com");
    assert_eq!(records[1].priority, 30);
    assert_eq!(records[1].hostname, "mx3.example.com");
}

#[test]
fn test_parse_dig_output_skips_comment_lines() {
    let tester = MxTester::new("example.com".to_string());
    let output = b";; communications error to 127.0.0.1#53\n10 mx1.example.com.\n";

    let records = tester
        .parse_dig_output(output)
        .expect("comment lines should be ignored");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].priority, 10);
    assert_eq!(records[0].hostname, "mx1.example.com");
}

#[test]
fn test_generate_mx_summary() {
    let mx1 = MxRecord {
        priority: 10,
        hostname: "mx1.example.com".to_string(),
    };
    let mx2 = MxRecord {
        priority: 20,
        hostname: "mx2.example.com".to_string(),
    };

    let rating = RatingResult {
        grade: Grade::A,
        score: 95,
        certificate_score: 90,
        protocol_score: 95,
        key_exchange_score: 95,
        cipher_strength_score: 95,
        warnings: vec![],
    };

    let ok_result = ScanResults {
        rating: Some(RatingResults {
            ssl_rating: Some(rating),
        }),
        ..Default::default()
    };

    let results: Vec<(MxRecord, Result<ScanResults>)> = vec![
        (mx1, Ok(ok_result)),
        (mx2, Err(TlsError::Other("fail".to_string()))),
    ];

    let summary = MxTester::generate_mx_summary(&results);
    assert!(summary.contains("MX RECORDS SCAN SUMMARY"));
    assert!(summary.contains("Successful"));
    assert!(summary.contains("Failed"));
    assert!(summary.contains("A"));
}

#[test]
fn test_parse_dig_output_rejects_invalid_priority() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"x mx.example.com.\n";

    let err = tester
        .parse_dig_output(output)
        .expect_err("invalid MX priority should fail");
    assert!(err.to_string().contains("Invalid dig MX priority"));
}

#[test]
fn test_parse_nslookup_output_rejects_invalid_priority() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"example.com mail exchanger = x mx.example.com.\n";

    let err = tester
        .parse_nslookup_output(output)
        .expect_err("invalid MX priority should fail");
    assert!(err.to_string().contains("Invalid nslookup MX priority"));
}

#[test]
fn test_generate_mx_summary_without_grades() {
    let mx = MxRecord {
        priority: 5,
        hostname: "mx.example.com".to_string(),
    };

    let results: Vec<(MxRecord, Result<ScanResults>)> = vec![(mx, Ok(ScanResults::default()))];
    let summary = MxTester::generate_mx_summary(&results);

    assert!(summary.contains("Individual MX Server Results"));
    assert!(!summary.contains("SSL Labs Grade Distribution"));
}

#[test]
fn test_generate_mx_summary_error_line() {
    let mx = MxRecord {
        priority: 5,
        hostname: "mx.example.com".to_string(),
    };
    let results: Vec<(MxRecord, Result<ScanResults>)> =
        vec![(mx, Err(TlsError::Other("fail".to_string())))];

    let summary = MxTester::generate_mx_summary(&results);
    assert!(summary.contains("ERROR"));
    assert!(summary.contains("fail"));
}

#[test]
fn test_generate_mx_summary_grade_distribution_multiple() {
    let mx1 = MxRecord {
        priority: 10,
        hostname: "mx1.example.com".to_string(),
    };
    let mx2 = MxRecord {
        priority: 20,
        hostname: "mx2.example.com".to_string(),
    };

    let rating_a = RatingResult {
        grade: Grade::A,
        score: 95,
        certificate_score: 90,
        protocol_score: 95,
        key_exchange_score: 95,
        cipher_strength_score: 95,
        warnings: vec![],
    };
    let rating_b = RatingResult {
        grade: Grade::B,
        score: 70,
        certificate_score: 80,
        protocol_score: 70,
        key_exchange_score: 70,
        cipher_strength_score: 70,
        warnings: vec![],
    };

    let ok_a = ScanResults {
        rating: Some(RatingResults {
            ssl_rating: Some(rating_a),
        }),
        ..Default::default()
    };

    let ok_b = ScanResults {
        rating: Some(RatingResults {
            ssl_rating: Some(rating_b),
        }),
        ..Default::default()
    };

    let results: Vec<(MxRecord, Result<ScanResults>)> = vec![(mx1, Ok(ok_a)), (mx2, Ok(ok_b))];

    let summary = MxTester::generate_mx_summary(&results);
    assert!(summary.contains("SSL Labs Grade Distribution"));
    assert!(summary.contains("A: 1"));
    assert!(summary.contains("B: 1"));
}

#[test]
fn test_parse_dig_output_empty() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"";
    let records = tester
        .parse_dig_output(output)
        .expect("test assertion should succeed");
    assert!(records.is_empty());
}

#[test]
fn test_parse_dig_output_skips_null_mx() {
    let tester = MxTester::new("example.com".to_string());
    let records = tester
        .parse_dig_output(b"0 .\n")
        .expect("null MX should parse");

    assert!(records.is_empty());
}

#[test]
fn test_parse_nslookup_output_empty() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"example.com has no mail exchanger\n";
    let records = tester
        .parse_nslookup_output(output)
        .expect("test assertion should succeed");
    assert!(records.is_empty());
}

#[test]
fn test_parse_nslookup_output_skips_null_mx() {
    let tester = MxTester::new("example.com".to_string());
    let records = tester
        .parse_nslookup_output(b"example.com mail exchanger = 0 .\n")
        .expect("null MX should parse");

    assert!(records.is_empty());
}

#[test]
fn test_generate_mx_summary_with_failures() {
    let mx = MxRecord {
        priority: 10,
        hostname: "mx.example.com".to_string(),
    };
    let results: Vec<(MxRecord, Result<ScanResults>)> = vec![
        (mx.clone(), Ok(ScanResults::default())),
        (mx, Err(TlsError::Other("fail".to_string()))),
    ];

    let summary = MxTester::generate_mx_summary(&results);
    assert!(summary.contains("Failed"));
}

#[test]
fn test_parse_nslookup_output_trims_dot_and_spaces() {
    let tester = MxTester::new("example.com".to_string());
    let output = b"example.com mail exchanger = 10 mx.example.com.  \n";
    let records = tester
        .parse_nslookup_output(output)
        .expect("test assertion should succeed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].hostname, "mx.example.com");
}

#[test]
fn test_synthetic_backend_ip_does_not_collide_at_u16_boundary() {
    assert_ne!(synthetic_backend_ip(65_534), synthetic_backend_ip(65_535));
}

#[test]
fn test_aggregate_scan_results_for_domain_is_conservative() {
    let supported = ProtocolTestResult {
        protocol: Protocol::TLS12,
        supported: true,
        inconclusive: false,
        preferred: false,
        ciphers_count: 0,
        handshake_time_ms: None,
        heartbeat_enabled: None,
        session_resumption_caching: None,
        session_resumption_tickets: None,
        secure_renegotiation: None,
    };
    let unsupported = ProtocolTestResult {
        supported: false,
        inconclusive: false,
        ..supported.clone()
    };

    let results: Vec<(MxRecord, Result<ScanResults>)> = vec![
        (
            MxRecord {
                priority: 10,
                hostname: "mx1.example.com".to_string(),
            },
            Ok(ScanResults {
                protocols: vec![supported],
                ..Default::default()
            }),
        ),
        (
            MxRecord {
                priority: 20,
                hostname: "mx2.example.com".to_string(),
            },
            Ok(ScanResults {
                protocols: vec![unsupported],
                ..Default::default()
            }),
        ),
    ];

    let aggregate = MxTester::aggregate_scan_results_for_domain("example.com", &results).unwrap();

    assert_eq!(aggregate.target, "example.com:25");
    assert!(
        aggregate
            .protocols
            .iter()
            .any(|protocol| protocol.protocol == Protocol::TLS12 && !protocol.supported)
    );
}

#[test]
fn test_aggregate_scan_results_marks_vulnerabilities_inconclusive_when_mx_fails() {
    let results: Vec<(MxRecord, Result<ScanResults>)> = vec![
        (
            MxRecord {
                priority: 10,
                hostname: "mx1.example.com".to_string(),
            },
            Ok(ScanResults {
                vulnerabilities: vec![crate::vulnerabilities::VulnerabilityResult {
                    vuln_type: crate::vulnerabilities::VulnerabilityType::Heartbleed,
                    vulnerable: false,
                    inconclusive: false,
                    details: "not vulnerable".to_string(),
                    cve: None,
                    cwe: None,
                    severity: crate::vulnerabilities::Severity::High,
                }],
                ..Default::default()
            }),
        ),
        (
            MxRecord {
                priority: 20,
                hostname: "mx2.example.com".to_string(),
            },
            Err(TlsError::Other("connection failed".to_string())),
        ),
    ];

    let aggregate = MxTester::aggregate_scan_results_for_domain("example.com", &results).unwrap();

    assert_eq!(aggregate.vulnerabilities.len(), 1);
    assert!(aggregate.vulnerabilities[0].inconclusive);
    assert!(
        aggregate.vulnerabilities[0]
            .details
            .contains("incomplete MX coverage")
    );
}

#[test]
fn test_aggregate_scan_results_warns_when_clean_mx_coverage_is_partial() {
    let results: Vec<(MxRecord, Result<ScanResults>)> = vec![
        (
            MxRecord {
                priority: 10,
                hostname: "mx1.example.com".to_string(),
            },
            Ok(ScanResults::default()),
        ),
        (
            MxRecord {
                priority: 20,
                hostname: "mx2.example.com".to_string(),
            },
            Err(TlsError::Other("connection failed".to_string())),
        ),
    ];

    let aggregate = MxTester::aggregate_scan_results_for_domain("example.com", &results).unwrap();

    assert!(aggregate.vulnerabilities.is_empty());
    assert!(
        aggregate
            .scan_metadata
            .human_warnings
            .iter()
            .any(|warning| warning.contains("Incomplete MX coverage"))
    );
}
