use super::*;

#[test]
fn test_ids_friendly_applies_conservative_throttle() {
    let mut args = Args::default();
    args.http.ids_friendly = true;
    let request = args.to_scan_request().expect("scan request should build");
    let expected = crate::utils::ids_friendly::IdsFriendlyConfig::default().min_delay_ms;
    assert_eq!(request.connection.sleep, Some(expected));
}

#[test]
fn test_compliance_framework_forces_full_scan_and_vulnerability_phase() {
    let mut args = Args::default();
    args.compliance.framework = Some("pci-dss-v4".to_string());
    let request = args.to_scan_request().expect("scan request should build");
    assert!(
        request.scan.scope.full,
        "a compliance scan must run a full scan so its rules see complete data"
    );
    assert!(
        request.should_run_vulnerability_phase(),
        "a compliance scan must run the vulnerability phase, otherwise a vulnerability-free requirement passes vacuously"
    );
}

#[test]
fn test_policy_forces_full_scan_and_vulnerability_phase() {
    let mut args = Args::default();
    args.compliance.policy = Some(std::path::PathBuf::from("policy.yaml"));
    let request = args.to_scan_request().expect("scan request should build");
    assert!(request.scan.scope.full);
    assert!(request.should_run_vulnerability_phase());
}

#[test]
fn test_default_scan_without_compliance_does_not_force_full() {
    let args = Args::default();
    let request = args.to_scan_request().expect("scan request should build");
    assert!(
        !request.scan.scope.full,
        "a plain scan must not be forced to full by the compliance wiring"
    );
}

#[test]
fn test_explicit_sleep_overrides_ids_friendly_throttle() {
    let mut args = Args::default();
    args.http.ids_friendly = true;
    args.connection.sleep = Some(250);
    let request = args.to_scan_request().expect("scan request should build");
    assert_eq!(request.connection.sleep, Some(250));
}

#[test]
fn test_validate_conflicting_ip_flags() {
    let args = Args {
        network: NetworkArgs {
            test_all_ips: true,
            first_ip_only: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_ip_with_test_all_ips_conflict() {
    let args = Args {
        ip: Some("127.0.0.1".to_string()),
        network: NetworkArgs {
            test_all_ips: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_ip_with_first_ip_only_conflict() {
    let args = Args {
        ip: Some("127.0.0.1".to_string()),
        network: NetworkArgs {
            first_ip_only: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_scan_all_ips_requires_single_target() {
    let args = Args {
        network: NetworkArgs {
            scan_all_ips: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_scan_all_ips_conflicts_with_test_all_ips() {
    let args = Args {
        target: Some("example.com:443".to_string()),
        network: NetworkArgs {
            scan_all_ips: true,
            test_all_ips: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_xmpphost_requires_xmpp_starttls() {
    let args = Args {
        target: Some("example.com:5222".to_string()),
        starttls: StarttlsArgs {
            xmpphost: Some("chat.example.com".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_invalid_mx_domain() {
    let args = Args {
        mx_domain: Some("example..com".to_string()),
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_parallel_requires_mass_or_mx_mode() {
    let args = Args {
        target: Some("example.com:443".to_string()),
        network: NetworkArgs {
            parallel: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_custom_max_parallel_requires_mass_or_mx_mode() {
    let args = Args {
        target: Some("example.com:443".to_string()),
        network: NetworkArgs {
            max_parallel: DEFAULT_MAX_PARALLEL + 1,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_mx_rejects_json_multi_ip() {
    let args = Args {
        mx_domain: Some("example.com".to_string()),
        output: OutputArgs {
            json_multi_ip: Some(std::path::PathBuf::from("multi-ip.json")),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_json_multi_ip_requires_test_all_ips() {
    let args = Args {
        target: Some("example.com:443".to_string()),
        output: OutputArgs {
            json_multi_ip: Some(std::path::PathBuf::from("multi-ip.json")),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_validate_rejects_invalid_color_mode() {
    let args = Args::parse_with_sources_from(["cipherrun", "example.com:443", "--color", "4"])
        .expect("parse should succeed");

    assert!(args.validate().is_err());
}

#[test]
fn test_validate_accepts_supported_color_modes() {
    for color in 0..=3 {
        let args = Args::parse_with_sources_from([
            "cipherrun",
            "example.com:443",
            "--color",
            &color.to_string(),
        ])
        .expect("parse should succeed");

        assert!(
            args.validate().is_ok(),
            "color mode {color} should be valid"
        );
    }
}

#[test]
fn test_run_default_suite_flags() {
    let parsed = Args::parse_with_sources_from(["cipherrun"]).expect("parse should succeed");
    let args = parsed;
    assert!(
        args.run_default_suite()
            .expect("default suite should resolve")
    );

    let args = Args {
        scan: ScanArgs {
            protocols: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
}

#[test]
fn test_vulnerability_flags() {
    let args = Args::default();
    assert!(
        !args
            .test_vulnerabilities()
            .expect("vulnerability setting should resolve")
    );

    let args = Args {
        scan: ScanArgs {
            breach: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        args.test_vulnerabilities()
            .expect("vulnerability setting should resolve")
    );
}

#[test]
fn test_effective_sni() {
    let mut args = Args::default();
    assert_eq!(args.effective_sni("example.com"), "example.com");

    args.tls.sni_name = Some("custom.test".to_string());
    assert_eq!(args.effective_sni("example.com"), "custom.test");
}

#[test]
fn test_protocols_to_test_flags() {
    let args = Args {
        scan: ScanArgs {
            ssl2: true,
            tls13: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let protocols = args
        .protocols_to_test()
        .expect("protocols should resolve")
        .unwrap();
    assert_eq!(
        protocols,
        vec![
            crate::protocols::Protocol::SSLv2,
            crate::protocols::Protocol::TLS13
        ]
    );

    let args = Args {
        scan: ScanArgs {
            tlsall: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let protocols = args
        .protocols_to_test()
        .expect("protocols should resolve")
        .unwrap();
    assert_eq!(
        protocols,
        vec![
            crate::protocols::Protocol::TLS10,
            crate::protocols::Protocol::TLS11,
            crate::protocols::Protocol::TLS12,
            crate::protocols::Protocol::TLS13,
        ]
    );

    let args = Args::default();
    assert!(
        args.protocols_to_test()
            .expect("protocols should resolve")
            .is_none()
    );
}

#[test]
fn test_retry_config() {
    let args = Args {
        connection: ConnectionArgs {
            no_retry: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        args.retry_config()
            .expect("retry config should resolve")
            .is_none()
    );

    let args = Args {
        connection: ConnectionArgs {
            max_retries: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        args.retry_config()
            .expect("retry config should resolve")
            .is_none()
    );

    let args = Args {
        connection: ConnectionArgs {
            max_retries: 5,
            retry_backoff_ms: 250,
            max_backoff_ms: 2000,
            ..Default::default()
        },
        ..Default::default()
    };
    let cfg = args
        .retry_config()
        .expect("retry config should resolve")
        .expect("should return retry config");
    assert_eq!(cfg.max_retries, 5);
    assert_eq!(cfg.initial_backoff, std::time::Duration::from_millis(250));
    assert_eq!(cfg.max_backoff, std::time::Duration::from_millis(2000));
}

#[test]
fn test_has_certificate_filters() {
    let mut args = Args::default();
    assert!(!args.has_certificate_filters());

    args.cert_filters.filter_expired = true;
    assert!(args.has_certificate_filters());
}

#[test]
fn test_run_default_suite_disabled_by_client_simulation() {
    let args = Args {
        fingerprint: FingerprintArgs {
            client_simulation: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
}

#[test]
fn test_to_scan_request_preserves_functional_scan_flags() {
    let args = Args {
        scan: ScanArgs {
            cipher_per_proto: true,
            server_defaults: true,
            heartbleed: true,
            disable_rating: true,
            fast: true,
            ocsp: true,
            show_certificates: true,
            pre_handshake: true,
            probe_status: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let request = args.to_scan_request().expect("scan request should build");

    assert!(request.scan.ciphers.cipher_per_proto);
    assert!(request.scan.ciphers.server_defaults);
    assert!(request.scan.vulns.heartbleed);
    assert!(request.scan.prefs.disable_rating);
    assert!(request.scan.prefs.fast);
    assert!(request.scan.certs.ocsp);
    assert!(request.scan.certs.analyze_certificates);
    assert!(request.scan.prefs.pre_handshake);
    assert!(request.scan.prefs.probe_status);
}

#[test]
fn test_show_certificates_is_standalone_scan_workload() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: ScanArgs {
            all: false,
            show_certificates: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let request = args.to_scan_request().expect("scan request should build");

    assert!(request.scan.certs.analyze_certificates);
    assert!(request.validate_for_scan().is_ok());
    assert!(request.should_run_certificate_phase());
}

#[test]
fn test_run_default_suite_respects_all_false() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: ScanArgs {
            all: false,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
}

#[test]
fn test_parse_with_sources_tracks_explicit_fingerprint_flags() {
    let args = Args::parse_with_sources_from(["cipherrun", "--ja3=false", "--jarm=true"])
        .expect("parse should succeed");

    assert!(args.fingerprint_flag_sources.ja3_explicit);
    assert!(!args.fingerprint_flag_sources.ja3s_explicit);
    assert!(args.fingerprint_flag_sources.jarm_explicit);
}

#[test]
fn test_to_scan_request_preserves_explicit_fingerprint_sources() {
    let args = Args::parse_with_sources_from(["cipherrun", "--all=false", "--ja3=true"])
        .expect("parse should succeed");

    let request = args.to_scan_request().expect("scan request should build");

    assert!(request.fingerprint.explicit_ja3);
    assert!(!request.fingerprint.explicit_ja3s);
    assert!(!request.fingerprint.explicit_jarm);
    assert!(request.should_run_ja3_fingerprint());
    assert!(!request.should_run_ja3s_fingerprint());
    assert!(!request.should_run_jarm_fingerprint());
}

#[test]
fn test_explicit_positive_fingerprint_request_disables_default_suite() {
    let args =
        Args::parse_with_sources_from(["cipherrun", "--ja3=true"]).expect("parse should succeed");

    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
    assert!(
        args.to_scan_request()
            .expect("scan request should build")
            .should_run_ja3_fingerprint()
    );
}

#[test]
fn test_explicit_negative_fingerprint_flag_keeps_default_suite() {
    let args =
        Args::parse_with_sources_from(["cipherrun", "--ja3=false"]).expect("parse should succeed");

    assert!(
        args.run_default_suite()
            .expect("default suite should resolve")
    );
    assert!(
        !args
            .to_scan_request()
            .expect("scan request should build")
            .should_run_ja3_fingerprint()
    );
}

#[test]
fn test_probe_status_flag_disables_default_suite() {
    let args = Args::parse_with_sources_from(["cipherrun", "--probe-status"])
        .expect("parse should succeed");

    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
}

#[test]
fn test_pre_handshake_flag_disables_default_suite() {
    let args = Args::parse_with_sources_from(["cipherrun", "--pre-handshake"])
        .expect("parse should succeed");

    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
}

#[test]
fn test_ocsp_flag_disables_default_suite() {
    let args =
        Args::parse_with_sources_from(["cipherrun", "--ocsp"]).expect("parse should succeed");

    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
}

#[test]
fn test_client_simulation_flag_disables_default_suite() {
    let args = Args::parse_with_sources_from(["cipherrun", "--client-simulation"])
        .expect("parse should succeed");

    assert!(
        !args
            .run_default_suite()
            .expect("default suite should resolve")
    );
    assert!(
        args.to_scan_request()
            .expect("scan request should build")
            .should_run_client_simulation_phase()
    );
}

#[test]
fn test_validate_rejects_invalid_compliance_format() {
    let args = Args {
        compliance: ComplianceArgs {
            format: "jsno".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_validate_rejects_invalid_policy_format() {
    let args = Args {
        compliance: ComplianceArgs {
            policy_format: "cvs".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_validate_rejects_invalid_compliance_severity() {
    let args = Args {
        compliance: ComplianceArgs {
            severity: Some("info".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_to_scan_request_preserves_proxy_and_resolvers() {
    let args = Args {
        network: NetworkArgs {
            proxy: Some("proxy.example.com:8080".to_string()),
            resolvers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };

    let request = args.to_scan_request().expect("scan request should build");

    assert_eq!(
        request.network.proxy.as_deref(),
        Some("proxy.example.com:8080")
    );
    assert_eq!(
        request.network.resolvers,
        vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
    );
}

#[test]
fn test_validate_rejects_invalid_proxy() {
    let args = Args {
        network: NetworkArgs {
            proxy: Some("proxy.example.com:notaport".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_validate_rejects_append_and_overwrite() {
    let args = Args {
        output: OutputArgs {
            append: true,
            overwrite: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_validate_rejects_mass_scan_csv_export() {
    let args = Args {
        input_file: Some(std::path::PathBuf::from("targets.txt")),
        output: OutputArgs {
            csv: Some(std::path::PathBuf::from("report.csv")),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_validate_rejects_mass_scan_html_export() {
    let args = Args {
        input_file: Some(std::path::PathBuf::from("targets.txt")),
        output: OutputArgs {
            html: Some(std::path::PathBuf::from("report.html")),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_validate_rejects_mass_scan_xml_export() {
    let args = Args {
        input_file: Some(std::path::PathBuf::from("targets.txt")),
        output: OutputArgs {
            xml: Some(std::path::PathBuf::from("report.xml")),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(args.validate().is_err());
}
