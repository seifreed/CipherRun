use super::*;
use std::net::IpAddr;
use std::sync::Once;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
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
fn test_generate_recommendations_variants() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);

    let ok_result = GreaseResult {
        tolerates_grease: true,
        inconclusive: false,
        direct_grease_test_performed: true,
        issues: vec![],
        details: vec![],
        tests_performed: vec![],
    };
    let ok_recs = tester.generate_recommendations(&ok_result);
    assert!(ok_recs.iter().any(|r| r.contains("RFC 8701")));

    let bad_result = GreaseResult {
        tolerates_grease: false,
        inconclusive: false,
        direct_grease_test_performed: true,
        issues: vec!["issue".to_string()],
        details: vec![],
        tests_performed: vec![],
    };
    let bad_recs = tester.generate_recommendations(&bad_result);
    assert!(bad_recs.iter().any(|r| r.contains("handle GREASE values")));
    assert!(
        bad_recs
            .iter()
            .any(|r| r.contains("Address the identified issues"))
    );
}

#[test]
fn test_grease_result() {
    let result = GreaseResult {
        tolerates_grease: true,
        inconclusive: false,
        direct_grease_test_performed: true,
        issues: vec![],
        details: vec!["Test".to_string()],
        tests_performed: vec!["GREASE cipher suites".to_string()],
    };

    assert!(result.tolerates_grease);
    assert_eq!(result.details.len(), 1);
    assert_eq!(result.tests_performed.len(), 1);
}

#[test]
fn test_grease_report_fields() {
    let report = GreaseReport {
        grease_result: GreaseResult {
            tolerates_grease: false,
            inconclusive: true,
            direct_grease_test_performed: false,
            issues: vec!["issue".to_string()],
            details: vec!["detail".to_string()],
            tests_performed: vec![],
        },
        recommendations: vec!["rec".to_string()],
    };

    assert!(!report.grease_result.tolerates_grease);
    assert_eq!(report.grease_result.issues.len(), 1);
    assert_eq!(report.recommendations.len(), 1);
}

#[test]
fn test_build_client_hello_with_grease_ciphers() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);

    let hello = tester
        .build_client_hello_with_grease_ciphers()
        .expect("test assertion should succeed");

    // Check it's a valid TLS handshake record
    assert_eq!(hello[0], 0x16); // Handshake
    assert_eq!(hello[5], 0x01); // ClientHello

    // Check that GREASE values are present
    let has_grease = hello
        .windows(2)
        .any(|w| w == [0x0A, 0x0A] || w == [0x1A, 0x1A]);
    assert!(has_grease, "ClientHello should contain GREASE values");
}

#[test]
fn test_build_client_hello_with_grease_extensions() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);

    let hello = tester
        .build_client_hello_with_grease_extensions()
        .expect("test assertion should succeed");

    assert_eq!(hello[0], 0x16);
    assert_eq!(hello[5], 0x01);
    assert!(hello.len() > 100);
}

#[test]
fn test_build_client_hello_with_grease_groups() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);

    let hello = tester
        .build_client_hello_with_grease_groups()
        .expect("test assertion should succeed");

    assert_eq!(hello[0], 0x16);
    assert_eq!(hello[5], 0x01);
}

#[test]
fn test_build_client_hello_combined_grease() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);

    let hello = tester
        .build_client_hello_combined_grease()
        .expect("test assertion should succeed");

    assert_eq!(hello[0], 0x16);
    assert_eq!(hello[5], 0x01);
}

async fn spawn_dummy_server(max_accepts: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut remaining = max_accepts;
        while remaining > 0 {
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
            remaining -= 1;
        }
    });
    addr
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
    install_crypto_provider();
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
    install_crypto_provider();
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
            .any(|issue| issue.contains("Baseline connection failed"))
    );
}

#[test]
fn test_grease_result_details_includes_issues() {
    let result = GreaseResult {
        tolerates_grease: false,
        inconclusive: true,
        direct_grease_test_performed: false,
        issues: vec!["Baseline connection failed".to_string()],
        details: vec!["Not tolerant".to_string()],
        tests_performed: vec![],
    };
    assert!(!result.tolerates_grease);
    assert!(result.details.iter().any(|d| d.contains("Not tolerant")));
    assert_eq!(result.issues.len(), 1);
}

#[test]
fn test_recommendations_count_increases_with_issues() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);

    let base_result = GreaseResult {
        tolerates_grease: false,
        inconclusive: true,
        direct_grease_test_performed: false,
        issues: Vec::new(),
        details: Vec::new(),
        tests_performed: Vec::new(),
    };
    let base_recs = tester.generate_recommendations(&base_result);

    let issue_result = GreaseResult {
        tolerates_grease: false,
        inconclusive: true,
        direct_grease_test_performed: false,
        issues: vec!["issue".to_string()],
        details: Vec::new(),
        tests_performed: Vec::new(),
    };
    let issue_recs = tester.generate_recommendations(&issue_result);

    assert!(issue_recs.len() > base_recs.len());
}

#[test]
fn test_tolerates_grease_logic() {
    let mut result = GreaseResult {
        tolerates_grease: false, // Will be computed
        inconclusive: false,
        direct_grease_test_performed: true,
        issues: vec![],
        details: vec!["✓ Server tolerates grease cipher suites".to_string()],
        tests_performed: vec!["test1".to_string()],
    };

    GreaseTester::finalize_grease_result(&mut result);
    assert!(result.tolerates_grease);
    assert!(!result.inconclusive);

    // When there are rejections, tolerates_grease should be false
    let mut result_with_rejection = GreaseResult {
        tolerates_grease: false,
        inconclusive: false,
        direct_grease_test_performed: true,
        issues: vec!["Server rejected GREASE cipher suites (violates RFC 8701)".to_string()],
        details: vec![],
        tests_performed: vec!["test1".to_string()],
    };

    GreaseTester::finalize_grease_result(&mut result_with_rejection);
    assert!(!result_with_rejection.tolerates_grease);
    assert!(!result_with_rejection.inconclusive);
}

#[test]
fn test_grease_partial_inconclusive_does_not_report_tolerant() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);
    let mut result = GreaseResult {
        tolerates_grease: false,
        inconclusive: false,
        direct_grease_test_performed: false,
        issues: vec![],
        details: vec!["✓ Baseline connection successful".to_string()],
        tests_performed: vec![],
    };

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
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap();
    let tester = GreaseTester::new(target);
    let mut result = GreaseResult {
        tolerates_grease: false,
        inconclusive: false,
        direct_grease_test_performed: false,
        issues: vec![],
        details: vec!["✓ Baseline connection successful".to_string()],
        tests_performed: vec![],
    };

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
