use super::*;
use crate::constants::{CONTENT_TYPE_APPLICATION_DATA, VERSION_TLS_1_2};

#[test]
fn test_poodle_result() {
    let result = PoodleTestResult {
        vulnerable: true,
        ssl3_supported: Some(true),
        tls_poodle: Some(false),
        details: "Test".to_string(),
        variants: Vec::new(),
    };
    assert!(result.vulnerable);
    assert_eq!(result.ssl3_supported, Some(true));
}

#[test]
fn test_poodle_variant_names() {
    assert_eq!(PoodleVariant::SslV3.name(), "POODLE (SSLv3)");
    assert_eq!(PoodleVariant::Tls.name(), "POODLE (TLS)");
    assert_eq!(PoodleVariant::ZombiePoodle.name(), "Zombie POODLE");
    assert_eq!(PoodleVariant::GoldenDoodle.name(), "GOLDENDOODLE");
    assert_eq!(PoodleVariant::SleepingPoodle.name(), "Sleeping POODLE");
    assert_eq!(
        PoodleVariant::OpenSsl0Length.name(),
        "OpenSSL 0-Length Fragment"
    );
}

#[test]
fn test_poodle_variant_cves() {
    assert_eq!(PoodleVariant::SslV3.cve(), "CVE-2014-3566");
    assert_eq!(PoodleVariant::Tls.cve(), "CVE-2014-8730");
    assert_eq!(PoodleVariant::ZombiePoodle.cve(), "CVE-2019-5592");
    assert_eq!(PoodleVariant::GoldenDoodle.cve(), "CVE-2019-5592");
    assert_eq!(PoodleVariant::SleepingPoodle.cve(), "CVE-2019-5592");
    assert_eq!(PoodleVariant::OpenSsl0Length.cve(), "CVE-2011-4576");
}

#[test]
fn test_poodle_variant_descriptions() {
    assert!(PoodleVariant::SslV3.description().contains("SSL 3.0"));
    assert!(PoodleVariant::Tls.description().contains("TLS"));
    assert!(
        PoodleVariant::OpenSsl0Length
            .description()
            .contains("Zero-length")
    );
}

#[test]
fn test_variant_result_structure() {
    let timing_data = TimingData {
        valid_padding_avg_ms: 15.5,
        invalid_padding_avg_ms: 10.2,
        timing_difference_ms: 5.3,
        samples_collected: 10,
    };

    let result = PoodleVariantResult {
        variant: PoodleVariant::SleepingPoodle,
        vulnerable: true,
        inconclusive: false,
        details: "Timing oracle detected".to_string(),
        timing_data: Some(timing_data),
    };

    assert!(result.vulnerable);
    assert_eq!(result.variant, PoodleVariant::SleepingPoodle);
    assert!(result.timing_data.is_some());

    let timing = result.timing_data.expect("test assertion should succeed");
    assert_eq!(timing.samples_collected, 10);
    assert_eq!(timing.timing_difference_ms, 5.3);
}

#[test]
fn test_variant_result_without_timing_data() {
    let result = PoodleVariantResult {
        variant: PoodleVariant::Tls,
        vulnerable: false,
        inconclusive: false,
        details: "No timing data".to_string(),
        timing_data: None,
    };

    assert!(!result.vulnerable);
    assert!(result.timing_data.is_none());
}

#[test]
fn test_ssl3_variant_result_inconclusive() {
    let result = super::PoodleTester::ssl3_variant_result(None);
    assert!(result.inconclusive);
    assert!(!result.vulnerable);
    assert!(result.details.contains("inconclusive"));
}

#[test]
fn test_cbc_probe_inconclusive_result() {
    let result = PoodleTester::cbc_inconclusive_result(PoodleVariant::GoldenDoodle);

    assert!(!result.vulnerable);
    assert!(result.inconclusive);
    assert!(result.details.contains("inconclusive"));
}

#[test]
fn test_malformed_record_building() {
    let target = crate::utils::network::Target::with_ips(
        "example.com".to_string(),
        443,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let _tester = PoodleTester::new(&target);

    // Test invalid padding valid MAC record
    let record = record_builder::build_record_invalid_padding_valid_mac();
    assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
    assert_eq!(record[1], (VERSION_TLS_1_2 >> 8) as u8);
    assert_eq!(record[2], (VERSION_TLS_1_2 & 0xff) as u8);
    assert!(record.len() > 48);

    // Verify padding is invalid (inconsistent bytes)
    let padding = &record[record.len() - 7..];
    let first = padding[0];
    assert!(
        padding.iter().any(|&b| b != first),
        "Padding should be inconsistent"
    );

    // Test valid padding invalid MAC record
    let record = record_builder::build_record_valid_padding_invalid_mac();
    assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);

    // Verify padding is valid (all bytes same)
    let padding = &record[record.len() - 7..];
    assert!(padding.iter().all(|&b| b == 0x06), "Padding should be 0x06");

    // Test zero-length record
    let record = record_builder::build_zero_length_record();
    assert_eq!(record.len(), 5);
    assert_eq!(record[3], 0x00);
    assert_eq!(record[4], 0x00);
}

#[test]
fn test_with_starttls_sets_hostname_and_mode() {
    let target = crate::utils::network::Target::with_ips(
        "example.com".to_string(),
        443,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let tester = PoodleTester::new(&target).with_starttls(
        Some(crate::starttls::StarttlsProtocol::XMPP),
        Some("xmpp.example.com".to_string()),
        true,
    );

    assert_eq!(tester.starttls, Some(crate::starttls::StarttlsProtocol::XMPP));
    assert_eq!(
        tester.starttls_hostname.as_deref(),
        Some("xmpp.example.com")
    );
    assert!(tester.starttls_server_mode);
}

#[test]
fn test_client_hello_cbc_structure() {
    let hello = record_builder::build_client_hello_cbc().expect("CBC ClientHello should build");

    // Verify TLS record header
    assert_eq!(hello[0], 0x16); // Handshake
    assert_eq!(hello[1], 0x03); // TLS 1.2 record layer
    assert_eq!(hello[2], 0x01); // TLS 1.0 record layer (standard)

    // Verify handshake type
    assert_eq!(hello[5], 0x01); // ClientHello

    // Verify TLS version in handshake (TLS 1.2)
    assert_eq!(hello[9], 0x03);
    assert_eq!(hello[10], 0x03);

    // Verify cipher suites present
    assert!(hello.len() > 50, "ClientHello should contain cipher suites");
}

#[test]
fn test_build_record_invalid_padding_invalid_mac() {
    let record = record_builder::build_record_invalid_padding_invalid_mac();

    assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
    let padding = &record[record.len() - 7..];
    let first = padding[0];
    assert!(padding.iter().any(|&b| b != first));
}

#[test]
fn test_build_malformed_record_dispatch() {
    let a = record_builder::build_malformed_record(MalformedRecordType::InvalidPaddingValidMac);
    let b = record_builder::build_malformed_record(MalformedRecordType::ValidPaddingInvalidMac);
    let c = record_builder::build_malformed_record(MalformedRecordType::InvalidPaddingInvalidMac);
    let d = record_builder::build_malformed_record(MalformedRecordType::ZeroLengthFragment);

    assert!(a.len() > d.len());
    assert!(b.len() > d.len());
    assert!(c.len() > d.len());
    assert_eq!(d.len(), 5);
}

#[test]
fn test_detect_response_oracle_alert_difference() {
    // A genuine oracle: both record types reliably alert, but with a
    // consistently different alert type across all samples.
    let alert = |code: u8| ServerResponse {
        connection_accepted: true,
        alert_type: Some(code),
        response_time_ms: 5.0,
        shows_differential_behavior: true,
    };
    let responses_a = vec![alert(20), alert(20), alert(20)];
    let responses_b = vec![alert(40), alert(40), alert(40)];

    assert!(oracle_detection::detect_response_oracle(
        &responses_a,
        &responses_b
    ));
}

#[test]
fn test_detect_response_oracle_timing_difference() {
    let responses_a = vec![
        ServerResponse {
            connection_accepted: true,
            alert_type: None,
            response_time_ms: 1.0,
            shows_differential_behavior: false,
        },
        ServerResponse {
            connection_accepted: true,
            alert_type: None,
            response_time_ms: 1.5,
            shows_differential_behavior: false,
        },
        ServerResponse {
            connection_accepted: true,
            alert_type: None,
            response_time_ms: 1.2,
            shows_differential_behavior: false,
        },
    ];
    // Stricter threshold (>3*stddev + 50ms): use a clearly large, low-variance
    // timing gap that survives the jitter guard.
    let responses_b = vec![
        ServerResponse {
            connection_accepted: true,
            alert_type: None,
            response_time_ms: 150.0,
            shows_differential_behavior: false,
        },
        ServerResponse {
            connection_accepted: true,
            alert_type: None,
            response_time_ms: 152.0,
            shows_differential_behavior: false,
        },
        ServerResponse {
            connection_accepted: true,
            alert_type: None,
            response_time_ms: 151.0,
            shows_differential_behavior: false,
        },
    ];

    assert!(oracle_detection::detect_response_oracle(
        &responses_a,
        &responses_b
    ));
}

#[test]
fn test_build_malformed_record_selector() {
    let record = record_builder::build_malformed_record(MalformedRecordType::ZeroLengthFragment);
    assert_eq!(record.len(), 5);
    assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
}

#[test]
fn test_detect_response_oracle_no_difference() {
    let responses_a = vec![
        ServerResponse {
            connection_accepted: false,
            alert_type: Some(40),
            response_time_ms: 5.0,
            shows_differential_behavior: false,
        },
        ServerResponse {
            connection_accepted: false,
            alert_type: Some(40),
            response_time_ms: 6.0,
            shows_differential_behavior: false,
        },
    ];
    let responses_b = vec![
        ServerResponse {
            connection_accepted: false,
            alert_type: Some(40),
            response_time_ms: 5.5,
            shows_differential_behavior: false,
        },
        ServerResponse {
            connection_accepted: false,
            alert_type: Some(40),
            response_time_ms: 5.2,
            shows_differential_behavior: false,
        },
    ];

    assert!(!oracle_detection::detect_response_oracle(
        &responses_a,
        &responses_b
    ));
    assert!(!oracle_detection::detect_response_oracle(&[], &responses_b));
}

#[test]
fn test_record_construction_variants() {
    let valid = record_builder::build_record_valid_padding_invalid_mac();
    assert_eq!(valid[0], CONTENT_TYPE_APPLICATION_DATA);
    assert_eq!(valid.len(), 60);
    assert!(valid[valid.len() - 7..].iter().all(|&b| b == 0x06));

    let invalid = record_builder::build_record_invalid_padding_invalid_mac();
    assert_eq!(invalid[0], CONTENT_TYPE_APPLICATION_DATA);
    assert_eq!(invalid.len(), 60);
    let unique_padding: std::collections::HashSet<u8> =
        invalid[invalid.len() - 7..].iter().copied().collect();
    assert!(unique_padding.len() > 1);

    let zero = record_builder::build_zero_length_record();
    assert_eq!(zero.len(), 5);
    assert_eq!(zero[0], CONTENT_TYPE_APPLICATION_DATA);
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_poodle_ssl3_modern_server() {
    let target = crate::utils::network::Target::parse("www.google.com:443")
        .await
        .expect("test assertion should succeed");
    let tester = PoodleTester::new(&target);

    let result = tester.test().await.expect("test assertion should succeed");

    assert_eq!(result.ssl3_supported, Some(false));
    assert!(!result.vulnerable);
}

#[tokio::test]
#[ignore] // Requires network access and vulnerable server
async fn test_all_variants_modern_server() {
    let target = crate::utils::network::Target::parse("www.google.com:443")
        .await
        .expect("test assertion should succeed");
    let tester = PoodleTester::new(&target);

    let result = tester
        .test_all_variants()
        .await
        .expect("test assertion should succeed");

    assert!(!result.vulnerable);
    assert_eq!(result.variants.len(), 6);

    for variant_result in &result.variants {
        println!(
            "{}: {}",
            variant_result.variant.name(),
            variant_result.details
        );
    }
}

#[tokio::test]
async fn test_poodle_inactive_target_is_inconclusive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let target = crate::utils::network::Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();
    let tester = PoodleTester::new(&target);
    let result = tester.test().await.expect("test should succeed");

    assert!(!result.vulnerable);
    assert_eq!(result.ssl3_supported, None);
    assert_eq!(result.tls_poodle, None);
    assert!(result.details.contains("inconclusive"), "{result:?}");
}
