use super::*;
use crate::protocols::Protocol;

#[test]
fn maps_full_scan_options_into_internal_request() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            proto: ScanRequestProto {
                enabled: true,
                ..Default::default()
            },
            ciphers: ScanRequestCiphers {
                each_cipher: true,
                ..Default::default()
            },
            vulns: ScanRequestVulns {
                vulnerabilities: true,
                ..Default::default()
            },
            prefs: ScanRequestPrefs {
                headers: true,
                ..Default::default()
            },
            scope: ScanRequestScope {
                all: true,
                full: true,
            },
            ..Default::default()
        },
        fingerprint: ScanRequestFingerprint {
            client_simulation: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert_eq!(request.target.as_deref(), Some("example.com:443"));
    assert!(request.scan.proto.enabled);
    assert!(request.scan.ciphers.each_cipher);
    assert!(request.scan.vulns.vulnerabilities);
    assert!(request.scan.prefs.headers);
    assert!(request.scan.scope.all);
    assert!(request.fingerprint.client_simulation);
}

#[test]
fn builds_protocol_filter_from_flags() {
    let request = ScanRequest {
        scan: ScanRequestScan {
            proto: ScanRequestProto {
                ssl2: true,
                tls13: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert_eq!(
        request.protocols_to_test(),
        Some(vec![Protocol::SSLv2, Protocol::TLS13])
    );
}

#[test]
fn rejects_conflicting_ip_scan_modes() {
    let request = ScanRequest {
        ip: Some("127.0.0.1".to_string()),
        network: ScanRequestNetwork {
            test_all_ips: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.validate_common().is_err());
}

#[test]
fn rejects_missing_target_for_scan() {
    let request = ScanRequest::default();
    assert!(request.validate_for_scan().is_err());
}

#[test]
fn rejects_target_without_effective_scan_workload() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        ..Default::default()
    };

    assert!(request.validate_for_scan().is_err());
}

#[test]
fn allows_probe_status_only_scan_requests() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            prefs: ScanRequestPrefs {
                probe_status: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.validate_for_scan().is_ok());
}

#[test]
fn rejects_hardfail_without_phone_out() {
    let request = ScanRequest {
        tls: ScanRequestTls {
            hardfail: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.validate_common().is_err());
}

#[test]
fn rejects_ssl_native_without_certificate_phase() {
    let request = ScanRequest {
        tls: ScanRequestTls {
            ssl_native: true,
            ..Default::default()
        },
        scan: ScanRequestScan {
            proto: ScanRequestProto {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.validate_common().is_err());
}

#[test]
fn rejects_additional_ca_without_certificate_phase() {
    let request = ScanRequest {
        tls: ScanRequestTls {
            add_ca: Some("extra-ca.pem".into()),
            ..Default::default()
        },
        scan: ScanRequestScan {
            proto: ScanRequestProto {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.validate_common().is_err());
}

#[test]
fn baseline_scan_requires_all_without_specific_focus() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.baseline_scan_requested());
    assert!(request.should_run_protocol_phase());
    assert!(request.should_run_cipher_phase());
    assert!(request.should_run_certificate_phase());
    assert!(!request.should_run_vulnerability_phase());
    assert!(request.should_calculate_rating());
}

#[test]
fn specific_vulnerability_focus_disables_baseline_scan() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            vulns: ScanRequestVulns {
                heartbleed: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.has_specific_scan_focus());
    assert!(!request.baseline_scan_requested());
    assert!(!request.should_run_protocol_phase());
    assert!(!request.should_run_cipher_phase());
    assert!(!request.should_run_certificate_phase());
    assert!(request.should_run_vulnerability_phase());
    assert!(!request.should_calculate_rating());
}

#[test]
fn explicit_positive_fingerprint_focus_disables_baseline_scan() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            ..Default::default()
        },
        fingerprint: ScanRequestFingerprint {
            explicit_ja3: true,
            ja3: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.has_specific_scan_focus());
    assert!(!request.baseline_scan_requested());
    assert!(!request.should_run_protocol_phase());
    assert!(!request.should_run_cipher_phase());
    assert!(!request.should_run_certificate_phase());
    assert!(!request.should_run_http_headers_phase());
    assert!(!request.should_run_client_simulation_phase());
    assert!(!request.should_run_alpn_phase());
    assert!(!request.should_run_intolerance_phase());
    assert!(!request.should_calculate_rating());
    assert!(request.should_run_ja3_fingerprint());
    assert!(!request.should_run_ja3s_fingerprint());
    assert!(!request.should_run_jarm_fingerprint());
}

#[test]
fn explicit_negative_fingerprint_flag_does_not_disable_baseline_scan() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            ..Default::default()
        },
        fingerprint: ScanRequestFingerprint {
            explicit_ja3: true,
            ja3: false,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!request.has_explicit_fingerprint_focus());
    assert!(request.baseline_scan_requested());
    assert!(!request.should_run_ja3_fingerprint());
    assert!(request.should_run_ja3s_fingerprint());
    assert!(request.should_run_jarm_fingerprint());
}

#[test]
fn rejects_rdp_with_starttls_negotiation() {
    let request = ScanRequest {
        starttls: ScanRequestStarttls {
            rdp: true,
            smtp: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.validate_common().is_err());
}

#[test]
fn all_false_disables_baseline_scan_even_with_target() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!request.baseline_scan_requested());
    assert!(!request.should_run_protocol_phase());
    assert!(!request.should_run_cipher_phase());
    assert!(!request.should_run_certificate_phase());
    assert!(!request.should_calculate_rating());
    assert!(request.validate_for_scan().is_err());
}

#[test]
fn cipher_focus_requests_full_enumeration() {
    let request = ScanRequest {
        scan: ScanRequestScan {
            ciphers: ScanRequestCiphers {
                server_preference: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.should_enumerate_all_ciphers());
}

#[test]
fn ocsp_runs_certificate_phase_without_baseline() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            certs: ScanRequestCerts {
                ocsp: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!request.baseline_scan_requested());
    assert!(request.should_run_certificate_phase());
    assert!(!request.should_calculate_rating());
}

#[test]
fn explicit_certificate_analysis_runs_without_baseline() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            certs: ScanRequestCerts {
                analyze_certificates: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.has_specific_scan_focus());
    assert!(!request.baseline_scan_requested());
    assert!(request.should_run_certificate_phase());
    assert!(!request.should_calculate_rating());
}

#[test]
fn probe_status_focus_disables_baseline_scan() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            prefs: ScanRequestPrefs {
                probe_status: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.has_specific_scan_focus());
    assert!(!request.baseline_scan_requested());
    assert!(!request.should_run_protocol_phase());
    assert!(!request.should_run_cipher_phase());
    assert!(!request.should_run_certificate_phase());
    assert!(!request.should_calculate_rating());
    assert!(request.should_collect_preflight_data());
}

#[test]
fn pre_handshake_focus_disables_baseline_scan() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            prefs: ScanRequestPrefs {
                pre_handshake: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.has_specific_scan_focus());
    assert!(!request.baseline_scan_requested());
    assert!(!request.should_run_protocol_phase());
    assert!(!request.should_run_cipher_phase());
    assert!(!request.should_run_certificate_phase());
    assert!(!request.should_run_http_headers_phase());
    assert!(!request.should_run_alpn_phase());
    assert!(!request.should_run_intolerance_phase());
    assert!(!request.should_calculate_rating());
    assert!(request.should_collect_preflight_data());
}

#[test]
fn explicit_client_simulation_runs_without_baseline() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: false,
                ..Default::default()
            },
            ..Default::default()
        },
        fingerprint: ScanRequestFingerprint {
            client_simulation: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.has_specific_scan_focus());
    assert!(!request.baseline_scan_requested());
    assert!(request.should_run_client_simulation_phase());
    assert!(!request.should_run_http_headers_phase());
    assert!(!request.should_run_alpn_phase());
    assert!(!request.should_run_intolerance_phase());
}

#[test]
fn explicit_header_focus_runs_without_other_advanced_baseline_phases() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            prefs: ScanRequestPrefs {
                headers: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!request.baseline_scan_requested());
    assert!(request.should_run_http_headers_phase());
    assert!(!request.should_run_client_simulation_phase());
    assert!(!request.should_run_alpn_phase());
    assert!(!request.should_run_intolerance_phase());
}

#[test]
fn signature_focus_does_not_drag_advanced_baseline_phases() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: true,
                ..Default::default()
            },
            ciphers: ScanRequestCiphers {
                show_sigs: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!request.baseline_scan_requested());
    assert!(!request.should_run_http_headers_phase());
    assert!(!request.should_run_client_simulation_phase());
    assert!(!request.should_run_alpn_phase());
    assert!(!request.should_run_intolerance_phase());
}

#[test]
fn all_false_disables_implicit_default_fingerprints() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!request.should_run_fingerprint_phase());
    assert!(!request.should_run_ja3_fingerprint());
    assert!(!request.should_run_ja3s_fingerprint());
    assert!(!request.should_run_jarm_fingerprint());
}

#[test]
fn explicit_fingerprint_request_survives_all_false() {
    let request = ScanRequest {
        target: Some("example.com:443".to_string()),
        scan: ScanRequestScan {
            scope: ScanRequestScope {
                all: false,
                ..Default::default()
            },
            ..Default::default()
        },
        fingerprint: ScanRequestFingerprint {
            ja3: true,
            explicit_ja3: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(request.should_run_fingerprint_phase());
    assert!(request.should_run_ja3_fingerprint());
    assert!(!request.should_run_ja3s_fingerprint());
    assert!(!request.should_run_jarm_fingerprint());
}
