use super::*;
use crate::vulnerabilities::test_support::spawn_dummy_server;
use std::net::IpAddr;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn loopback_target() -> Target {
    Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap()
}

fn loopback_tester() -> GreaseTester {
    GreaseTester::new(loopback_target())
}

fn grease_result(
    tolerates_grease: bool,
    inconclusive: bool,
    direct_grease_test_performed: bool,
    issues: &[&str],
    details: &[&str],
    tests_performed: &[&str],
) -> GreaseResult {
    GreaseResult {
        tolerates_grease,
        inconclusive,
        direct_grease_test_performed,
        issues: issues.iter().map(|value| value.to_string()).collect(),
        details: details.iter().map(|value| value.to_string()).collect(),
        tests_performed: tests_performed
            .iter()
            .map(|value| value.to_string())
            .collect(),
    }
}

fn assert_tls_client_hello(hello: &[u8]) {
    assert_eq!(hello[0], 0x16);
    assert_eq!(hello[5], 0x01);
}

#[test]
fn test_grease_values_defined() {
    assert!(!GREASE_CIPHER_SUITES.is_empty());
    assert!(!GREASE_EXTENSIONS.is_empty());
    assert!(!GREASE_SUPPORTED_GROUPS.is_empty());

    // Check that GREASE values follow the RFC 8701 pattern
    assert_eq!(GREASE_CIPHER_SUITES[0], 0x0A0A);
    assert_eq!(GREASE_CIPHER_SUITES[1], 0x1A1A);
    assert_eq!(GREASE_CIPHER_SUITES[2], 0x2A2A);
}

#[test]
fn test_grease_tester_creation() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec!["93.184.216.34".parse().unwrap()],
    )
    .unwrap();

    let tester = GreaseTester::new(target);
    assert_eq!(tester.target.hostname, "example.com");
}

#[test]
fn test_grease_probe_addrs_honors_all_ips() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([192, 0, 2, 1]), IpAddr::from([192, 0, 2, 2])],
    )
    .unwrap();

    let first = GreaseTester::new(target.clone()).probe_addrs().unwrap();
    assert_eq!(first.len(), 1);

    let all = GreaseTester::new(target)
        .with_test_all_ips(true)
        .probe_addrs()
        .unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_grease_merge_preserves_bad_or_unclear_address() {
    assert_eq!(
        GreaseTestOutcome::Tolerated.merge(GreaseTestOutcome::Inconclusive("timeout".to_string())),
        GreaseTestOutcome::Inconclusive("timeout".to_string())
    );
    assert_eq!(
        GreaseTestOutcome::Inconclusive("timeout".to_string()).merge(GreaseTestOutcome::Rejected),
        GreaseTestOutcome::Rejected
    );
}

#[test]
fn test_generate_recommendations_variants() {
    let tester = loopback_tester();

    let ok_result = grease_result(true, false, true, &[], &[], &[]);
    let ok_recs = tester.generate_recommendations(&ok_result);
    assert!(ok_recs.iter().any(|r| r.contains("RFC 8701")));

    let bad_result = grease_result(false, false, true, &["issue"], &[], &[]);
    let bad_recs = tester.generate_recommendations(&bad_result);
    assert!(bad_recs.iter().any(|r| r.contains("handle GREASE values")));
    assert!(
        bad_recs
            .iter()
            .any(|r| r.contains("Address the identified issues"))
    );

    let inconclusive_result = grease_result(
        false,
        true,
        true,
        &[],
        &["GREASE extensions test inconclusive: timeout"],
        &["GREASE extensions"],
    );
    let inconclusive_recs = tester.generate_recommendations(&inconclusive_result);
    assert!(
        inconclusive_recs
            .iter()
            .any(|r| r.contains("could not be determined"))
    );
    assert!(
        !inconclusive_recs
            .iter()
            .any(|r| r.contains("handle GREASE values")),
        "inconclusive GREASE results must not be reported as confirmed intolerance"
    );
}

#[test]
fn test_grease_result() {
    let result = grease_result(true, false, true, &[], &["Test"], &["GREASE cipher suites"]);

    assert!(result.tolerates_grease);
    assert_eq!(result.details.len(), 1);
    assert_eq!(result.tests_performed.len(), 1);
}

#[test]
fn test_grease_report_fields() {
    let report = GreaseReport {
        grease_result: grease_result(false, true, false, &["issue"], &["detail"], &[]),
        recommendations: vec!["rec".to_string()],
    };

    assert!(!report.grease_result.tolerates_grease);
    assert_eq!(report.grease_result.issues.len(), 1);
    assert_eq!(report.recommendations.len(), 1);
}

#[test]
fn test_build_client_hello_with_grease_ciphers() {
    let tester = loopback_tester();

    let hello = tester
        .build_client_hello_with_grease_ciphers()
        .expect("test assertion should succeed");

    // Check it's a valid TLS handshake record
    assert_tls_client_hello(&hello);

    // Check that GREASE values are present
    let has_grease = hello
        .windows(2)
        .any(|w| w == [0x0A, 0x0A] || w == [0x1A, 0x1A]);
    assert!(has_grease, "ClientHello should contain GREASE values");
}

#[test]
fn test_build_client_hello_with_grease_extensions() {
    let tester = loopback_tester();

    let hello = tester
        .build_client_hello_with_grease_extensions()
        .expect("test assertion should succeed");

    assert_tls_client_hello(&hello);
    assert!(hello.len() > 100);
}

#[test]
fn test_build_client_hello_with_grease_groups() {
    let tester = loopback_tester();

    let hello = tester
        .build_client_hello_with_grease_groups()
        .expect("test assertion should succeed");

    assert_tls_client_hello(&hello);
}

#[test]
fn test_build_client_hello_combined_grease() {
    let tester = loopback_tester();

    let hello = tester
        .build_client_hello_combined_grease()
        .expect("test assertion should succeed");

    assert_tls_client_hello(&hello);
}

async fn spawn_self_signed_tls_server(max_accepts: usize) -> std::net::SocketAddr {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    );

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();

    let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut remaining = max_accepts;
        while remaining > 0 {
            if let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    acceptor.accept(stream),
                )
                .await;
            }
            remaining -= 1;
        }
    });

    addr
}

#[tokio::test]
async fn test_grease_baseline_ignores_certificate_validation_errors() {
    crate::utils::insecure_tls::ensure_ring_provider();
    let addr = spawn_self_signed_tls_server(1).await;
    let target = Target::with_ips(
        "localhost".to_string(),
        addr.port(),
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();

    let tester = GreaseTester::new(target);
    let baseline_ok = tester.test_baseline_connection().await.unwrap();
    assert!(baseline_ok);
}

#[tokio::test]
async fn test_grease_tester_baseline_failure_path() {
    crate::utils::insecure_tls::ensure_ring_provider();
    let addr = spawn_dummy_server(5).await;
    let target = Target::with_ips(
        "127.0.0.1".to_string(),
        addr.port(),
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();

    let tester = GreaseTester::new(target);
    let result = tester.test().await.unwrap();
    assert!(!result.tolerates_grease);
    assert!(
        result.inconclusive,
        "baseline failure cannot be treated as a definitive GREASE result: {result:?}"
    );
    assert!(!result.direct_grease_test_performed);
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.contains("Baseline connection error"))
    );
}

#[test]
fn test_grease_result_details_includes_issues() {
    let result = grease_result(
        false,
        true,
        false,
        &["Baseline connection failed"],
        &["Not tolerant"],
        &[],
    );
    assert!(!result.tolerates_grease);
    assert!(result.details.iter().any(|d| d.contains("Not tolerant")));
    assert_eq!(result.issues.len(), 1);
}

#[test]
fn test_recommendations_count_increases_with_issues() {
    let tester = loopback_tester();

    let base_result = grease_result(false, true, false, &[], &[], &[]);
    let base_recs = tester.generate_recommendations(&base_result);

    let issue_result = grease_result(false, true, false, &["issue"], &[], &[]);
    let issue_recs = tester.generate_recommendations(&issue_result);

    assert!(issue_recs.len() > base_recs.len());
}

#[test]
fn test_tolerates_grease_logic() {
    let mut result = grease_result(
        false,
        false,
        true,
        &[],
        &["✓ Server tolerates grease cipher suites"],
        &["test1"],
    );

    GreaseTester::finalize_grease_result(&mut result);
    assert!(result.tolerates_grease);
    assert!(!result.inconclusive);

    // When there are rejections, tolerates_grease should be false
    let mut result_with_rejection = grease_result(
        false,
        false,
        true,
        &["Server rejected GREASE cipher suites (violates RFC 8701)"],
        &[],
        &["test1"],
    );

    GreaseTester::finalize_grease_result(&mut result_with_rejection);
    assert!(!result_with_rejection.tolerates_grease);
    assert!(!result_with_rejection.inconclusive);
}

#[test]
fn test_grease_partial_inconclusive_does_not_report_tolerant() {
    let tester = loopback_tester();
    let mut result = grease_result(
        false,
        false,
        false,
        &[],
        &["✓ Baseline connection successful"],
        &[],
    );

    tester.record_grease_test(
        &mut result,
        "GREASE cipher suites",
        Ok(GreaseTestOutcome::Tolerated),
    );
    tester.record_grease_test(
        &mut result,
        "GREASE extensions",
        Ok(GreaseTestOutcome::Inconclusive(
            "target closed connection".to_string(),
        )),
    );
    GreaseTester::finalize_grease_result(&mut result);

    assert!(!result.tolerates_grease);
    assert!(
        result.inconclusive,
        "partial GREASE evidence must stay inconclusive: {result:?}"
    );
}

#[test]
fn test_grease_all_category_inconclusive_ignores_baseline_success_detail() {
    let tester = loopback_tester();
    let mut result = grease_result(
        false,
        false,
        false,
        &[],
        &["✓ Baseline connection successful"],
        &[],
    );

    tester.record_grease_test(
        &mut result,
        "GREASE supported groups",
        Ok(GreaseTestOutcome::Inconclusive(
            "no TLS response after ClientHello".to_string(),
        )),
    );
    GreaseTester::finalize_grease_result(&mut result);

    assert!(!result.tolerates_grease);
    assert!(
        result.inconclusive,
        "baseline success detail cannot make GREASE support definitive: {result:?}"
    );
}
