use super::*;
use crate::constants::{CONTENT_TYPE_APPLICATION_DATA, VERSION_TLS_1_2};
use crate::utils::test_support::example_com_loopback_target;
use std::sync::Arc;

struct ScriptedProbeBackend {
    ssl3_supported: Option<bool>,
    cbc_connection: Option<bool>,
    cbc_supported: Option<bool>,
}

#[async_trait::async_trait]
impl network_probes::ProbeBackend for ScriptedProbeBackend {
    async fn ssl3_supported(
        &self,
        _target: &Target,
        _starttls: Option<crate::starttls::StarttlsProtocol>,
        _starttls_server_mode: bool,
    ) -> Result<Option<bool>> {
        Ok(self.ssl3_supported)
    }

    async fn cbc_connection_outcome(
        &self,
        _target: &Target,
        _starttls: Option<crate::starttls::StarttlsProtocol>,
        _starttls_hostname: Option<&str>,
        _starttls_server_mode: bool,
    ) -> Result<Option<bool>> {
        Ok(self.cbc_connection)
    }

    async fn supports_cbc_ciphers(
        &self,
        _target: &Target,
        _starttls: Option<crate::starttls::StarttlsProtocol>,
        _starttls_hostname: Option<&str>,
        _starttls_server_mode: bool,
    ) -> Result<Option<bool>> {
        Ok(self.cbc_supported)
    }

    async fn send_malformed_record(
        &self,
        _target: &Target,
        record_type: MalformedRecordType,
        _starttls: Option<crate::starttls::StarttlsProtocol>,
        _starttls_hostname: Option<&str>,
        _starttls_server_mode: bool,
    ) -> Result<ServerResponse> {
        Ok(ServerResponse {
            connection_accepted: true,
            alert_type: match record_type {
                MalformedRecordType::InvalidPaddingInvalidMac => None,
                MalformedRecordType::InvalidPaddingValidMac
                | MalformedRecordType::ValidPaddingInvalidMac => Some(20),
                MalformedRecordType::ZeroLengthFragment => None,
            },
            response_time_ms: 1.0,
            shows_differential_behavior: false,
        })
    }

    async fn measure_response_time(
        &self,
        _target: &Target,
        record_type: MalformedRecordType,
        _starttls: Option<crate::starttls::StarttlsProtocol>,
        _starttls_hostname: Option<&str>,
        _starttls_server_mode: bool,
    ) -> Result<f64> {
        Ok(match record_type {
            MalformedRecordType::ValidPaddingInvalidMac => 100.0,
            _ => 1.0,
        })
    }
}

fn scripted_tester(
    target: &Target,
    ssl3_supported: Option<bool>,
    cbc_connection: Option<bool>,
    cbc_supported: Option<bool>,
) -> PoodleTester<'_> {
    PoodleTester::new(target).with_probe_backend(Arc::new(ScriptedProbeBackend {
        ssl3_supported,
        cbc_connection,
        cbc_supported,
    }))
}

fn server_responses(
    connection_accepted: bool,
    alert_type: Option<u8>,
    response_times_ms: &[f64],
    shows_differential_behavior: bool,
) -> Vec<ServerResponse> {
    response_times_ms
        .iter()
        .map(|&response_time_ms| ServerResponse {
            connection_accepted,
            alert_type,
            response_time_ms,
            shows_differential_behavior,
        })
        .collect()
}

fn timing_samples(samples: &[f64]) -> TimingSampleSet {
    let mut set = TimingSampleSet::with_capacity(samples.len());
    for sample in samples {
        set.push(*sample);
    }
    set
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
        valid_padding_median_ms: 15.0,
        invalid_padding_median_ms: 10.0,
        valid_padding_p95_ms: 16.0,
        invalid_padding_p95_ms: 11.0,
        timing_difference_ms: 5.3,
        timing_difference_confidence_interval_95_ms: (4.1, 6.5),
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
fn test_ssl3_and_tls_variant_results_cover_each_outcome() {
    let supported = PoodleTester::ssl3_variant_result(Some(true));
    assert!(supported.vulnerable);
    assert!(!supported.inconclusive);

    let unsupported = PoodleTester::ssl3_variant_result(Some(false));
    assert!(!unsupported.vulnerable);
    assert!(!unsupported.inconclusive);

    for (outcome, vulnerable, inconclusive) in [
        (Some(true), true, false),
        (Some(false), false, false),
        (None, false, true),
    ] {
        let result = PoodleTester::tls_variant_result(outcome);
        assert_eq!(result.vulnerable, vulnerable);
        assert_eq!(result.inconclusive, inconclusive);
    }
}

#[test]
fn test_cbc_probe_inconclusive_result() {
    let result = PoodleTester::cbc_inconclusive_result(PoodleVariant::GoldenDoodle);

    assert!(!result.vulnerable);
    assert!(result.inconclusive);
    assert!(result.details.contains("inconclusive"));
}

#[test]
fn test_cbc_probe_not_supported_result() {
    let result = PoodleTester::cbc_not_supported_result(PoodleVariant::GoldenDoodle);

    assert!(!result.vulnerable);
    assert!(!result.inconclusive);
    assert_eq!(result.details, "CBC ciphers not supported - not vulnerable");
}

#[test]
fn response_oracle_result_covers_vulnerable_safe_and_insufficient_samples() {
    let vulnerable_a = server_responses(true, Some(20), &[5.0, 5.0, 5.0], true);
    let vulnerable_b = server_responses(true, None, &[5.0, 5.0, 5.0], false);
    let vulnerable = PoodleTester::response_oracle_result(
        PoodleVariant::ZombiePoodle,
        &vulnerable_a,
        &vulnerable_b,
        "oracle detected",
        "no oracle",
    );
    assert!(vulnerable.vulnerable);
    assert!(!vulnerable.inconclusive);
    assert!(vulnerable.details.contains("oracle detected"));

    let insufficient = PoodleTester::response_oracle_result(
        PoodleVariant::GoldenDoodle,
        &vulnerable_a[..2],
        &vulnerable_b[..2],
        "oracle detected",
        "no oracle",
    );
    assert!(!insufficient.vulnerable);
    assert!(insufficient.inconclusive);
    assert!(insufficient.details.contains("insufficient probe samples"));

    let same_a = server_responses(true, Some(20), &[5.0, 5.0, 5.0], true);
    let same_b = server_responses(true, Some(20), &[5.0, 5.0, 5.0], true);
    let safe = PoodleTester::response_oracle_result(
        PoodleVariant::GoldenDoodle,
        &same_a,
        &same_b,
        "oracle detected",
        "no oracle",
    );
    assert!(!safe.vulnerable);
    assert!(!safe.inconclusive);
    assert_eq!(safe.details, "no oracle");
}

#[test]
fn sleeping_poodle_analysis_covers_collection_and_statistical_outcomes() {
    let empty = TimingSampleSet::with_capacity(0);
    let sparse = timing_samples(&[10.0, 11.0]);
    let no_samples = PoodleTester::sleeping_poodle_result(&empty, &sparse);
    assert!(no_samples.inconclusive);
    assert!(
        no_samples
            .details
            .contains("could not collect timing samples")
    );

    let insufficient = PoodleTester::sleeping_poodle_result(&sparse, &sparse);
    assert!(insufficient.inconclusive);
    assert!(insufficient.details.contains("insufficient timing samples"));

    let low_variance = timing_samples(&[10.0; 10]);
    let slightly_slower = timing_samples(&[11.0; 10]);
    let below_threshold = PoodleTester::sleeping_poodle_result(&low_variance, &slightly_slower);
    assert!(below_threshold.details.contains("below threshold"));
    assert_eq!(
        below_threshold
            .timing_data
            .as_ref()
            .expect("sufficient samples should include statistics")
            .samples_collected,
        10
    );

    let valid_oracle = timing_samples(&[
        95.0, 105.0, 95.0, 105.0, 95.0, 105.0, 95.0, 105.0, 95.0, 105.0,
    ]);
    let invalid_oracle = timing_samples(&[9.0, 11.0, 9.0, 11.0, 9.0, 11.0, 9.0, 11.0, 9.0, 11.0]);
    let suspected = PoodleTester::sleeping_poodle_result(&valid_oracle, &invalid_oracle);
    assert!(!suspected.vulnerable);
    assert!(suspected.inconclusive);
    assert!(suspected.details.contains("Suspected Sleeping POODLE"));

    let uncertain = timing_samples(&[1.0, 300.0, 1.0, 300.0, 1.0, 300.0, 1.0, 300.0, 1.0, 300.0]);
    let steady = timing_samples(&[10.0; 10]);
    let unreliable = PoodleTester::sleeping_poodle_result(&uncertain, &steady);
    assert!(unreliable.inconclusive);
    assert!(unreliable.details.contains("measurement unreliable"));

    let variable_valid = timing_samples(&[
        80.0, 120.0, 80.0, 120.0, 80.0, 120.0, 80.0, 120.0, 80.0, 120.0,
    ]);
    let variable_invalid = timing_samples(&[
        60.0, 100.0, 60.0, 100.0, 60.0, 100.0, 60.0, 100.0, 60.0, 100.0,
    ]);
    let not_significant = PoodleTester::sleeping_poodle_result(&variable_valid, &variable_invalid);
    assert!(!not_significant.inconclusive);
    assert!(
        not_significant
            .details
            .contains("not statistically significant")
    );
}

#[tokio::test]
async fn test_openssl_zero_length_early_outcomes_do_not_probe_the_network() {
    let target = example_com_loopback_target(443);
    let tester = PoodleTester::new(&target);

    let unsupported = tester.test_openssl_0length(Some(false)).await.unwrap();
    assert_eq!(unsupported.variant, PoodleVariant::OpenSsl0Length);
    assert!(!unsupported.inconclusive);
    assert!(!unsupported.vulnerable);

    let unknown = tester.test_openssl_0length(None).await.unwrap();
    assert_eq!(unknown.variant, PoodleVariant::OpenSsl0Length);
    assert!(unknown.inconclusive);
    assert!(!unknown.vulnerable);
}

#[tokio::test(start_paused = true)]
async fn test_all_variants_exercises_deterministic_response_and_timing_probes() {
    let target = example_com_loopback_target(443);
    let tester = scripted_tester(&target, Some(true), Some(true), Some(true));

    let result = tester
        .test_all_variants()
        .await
        .expect("scripted probes should complete");

    assert_eq!(result.variants.len(), 6);
    assert_eq!(result.ssl3_supported, Some(true));
    assert_eq!(result.tls_poodle, Some(true));
    assert!(
        result.variants[2].vulnerable,
        "Zombie POODLE should detect the scripted alert oracle"
    );
    assert!(
        result.variants[3].vulnerable,
        "GOLDENDOODLE should detect the scripted alert oracle"
    );
    assert!(
        result.variants[4].inconclusive,
        "remote timing evidence must remain inconclusive"
    );
    assert!(
        result.variants[5].inconclusive,
        "the zero-length probe cannot confirm memory disclosure"
    );
}

#[tokio::test]
async fn test_variant_probe_outcomes_cover_unsupported_and_inconclusive_cbc() {
    let target = example_com_loopback_target(443);

    for cbc_supported in [Some(false), None] {
        let tester = scripted_tester(&target, Some(false), Some(false), cbc_supported);
        let response_oracle = tester
            .test_zombie_poodle()
            .await
            .expect("CBC outcome should be returned");
        assert!(!response_oracle.vulnerable);
        assert_eq!(response_oracle.inconclusive, cbc_supported.is_none());

        let timing_oracle = tester
            .test_sleeping_poodle()
            .await
            .expect("CBC outcome should be returned");
        assert!(!timing_oracle.vulnerable);
        assert_eq!(timing_oracle.inconclusive, cbc_supported.is_none());

        let zero_length = tester
            .test_openssl_0length(Some(true))
            .await
            .expect("CBC outcome should be returned");
        assert!(!zero_length.vulnerable);
        assert_eq!(zero_length.inconclusive, cbc_supported.is_none());
    }
}

#[test]
fn test_malformed_record_building() {
    let target = example_com_loopback_target(443);

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
    let target = example_com_loopback_target(443);

    let tester = PoodleTester::new(&target).with_starttls(
        Some(crate::starttls::StarttlsProtocol::XMPP),
        Some("xmpp.example.com".to_string()),
        true,
    );

    assert_eq!(
        tester.starttls,
        Some(crate::starttls::StarttlsProtocol::XMPP)
    );
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
    let responses_a = server_responses(true, Some(20), &[5.0, 5.0, 5.0], true);
    let responses_b = server_responses(true, Some(40), &[5.0, 5.0, 5.0], true);

    assert!(oracle_detection::detect_response_oracle(
        &responses_a,
        &responses_b
    ));
}

#[test]
fn test_detect_response_oracle_timing_difference() {
    let responses_a = server_responses(true, None, &[1.0, 1.5, 1.2], false);
    // Stricter threshold (>3*stddev + 50ms): use a clearly large, low-variance
    // timing gap that survives the jitter guard.
    let responses_b = server_responses(true, None, &[150.0, 152.0, 151.0], false);

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
    let responses_a = server_responses(false, Some(40), &[5.0, 6.0], false);
    let responses_b = server_responses(false, Some(40), &[5.5, 5.2], false);

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

#[tokio::test]
async fn test_all_poodle_variants_are_inconclusive_for_inactive_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let port = listener
        .local_addr()
        .expect("address should resolve")
        .port();
    drop(listener);
    let target = crate::utils::network::Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let result = PoodleTester::new(&target)
        .test_all_variants()
        .await
        .expect("variant checks should return diagnostic outcomes");

    assert!(!result.vulnerable);
    assert_eq!(result.variants.len(), 6);
    assert!(result.variants.iter().all(|variant| !variant.vulnerable));
    assert!(result.variants.iter().all(|variant| variant.inconclusive));
}
