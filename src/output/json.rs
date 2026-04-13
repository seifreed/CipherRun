// JSON Output Module

use crate::Result;
use crate::scanner::ScanResults;
use crate::scanner::multi_ip::MultiIpScanReport;

/// Generate JSON output from scan results
pub fn generate_json(results: &ScanResults, pretty: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(results)?)
    } else {
        Ok(serde_json::to_string(results)?)
    }
}

/// Generate JSON output from multi-IP scan report
pub fn generate_multi_ip_json(report: &MultiIpScanReport, pretty: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(report)?)
    } else {
        Ok(serde_json::to_string(report)?)
    }
}

/// Write JSON to file
pub fn write_json_file(results: &ScanResults, path: &str, pretty: bool) -> Result<()> {
    let json = generate_json(results, pretty)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Write multi-IP report JSON to file
pub fn write_multi_ip_json_file(
    report: &MultiIpScanReport,
    path: &str,
    pretty: bool,
) -> Result<()> {
    let json = generate_multi_ip_json(report, pretty)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::aggregation::AggregatedScanResult;
    use crate::scanner::inconsistency::{
        Inconsistency, InconsistencyDetails, InconsistencyType, SingleIpScanResult,
    };
    use crate::scanner::multi_ip::MultiIpScanReport;
    use crate::utils::network::Target;
    use crate::vulnerabilities::Severity;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_json_generation() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };

        let json = generate_json(&results, false).expect("test assertion should succeed");
        assert!(json.contains("example.com"));

        let pretty_json = generate_json(&results, true).expect("test assertion should succeed");
        assert!(pretty_json.contains("example.com"));
        assert!(pretty_json.contains("\n")); // Check for pretty printing
    }

    #[test]
    fn test_json_generation_compact_has_no_newlines() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };

        let json = generate_json(&results, false).expect("test assertion should succeed");
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_generate_json_compact_not_empty() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 42,
            ..Default::default()
        };
        let json = generate_json(&results, false).expect("test assertion should succeed");
        assert!(!json.is_empty());
    }

    static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_file_path(suffix: &str) -> PathBuf {
        let counter = FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
        #[cfg(unix)]
        let path = PathBuf::from(format!("/tmp/cipherrun-json-test-{}{}", counter, suffix));
        #[cfg(not(unix))]
        let path = std::env::temp_dir().join(format!("cipherrun-json-test-{}{}", counter, suffix));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn test_write_json_file() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 500,
            ..Default::default()
        };
        let path = temp_file_path(".json");
        write_json_file(&results, path.to_str().unwrap(), false)
            .expect("test assertion should succeed");
        let contents = std::fs::read_to_string(path).expect("test assertion should succeed");
        assert!(contents.contains("example.com"));
    }

    #[test]
    fn test_write_json_file_pretty_contains_newlines() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 500,
            ..Default::default()
        };
        let path = temp_file_path(".pretty.json");
        write_json_file(&results, path.to_str().unwrap(), true)
            .expect("test assertion should succeed");
        let contents = std::fs::read_to_string(path).expect("test assertion should succeed");
        assert!(contents.contains('\n'));
    }

    #[test]
    fn test_multi_ip_json_generation_and_write() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .expect("test assertion should succeed");

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut per_ip_results = HashMap::new();
        per_ip_results.insert(
            ip,
            SingleIpScanResult {
                ip,
                scan_result: ScanResults::default(),
                scan_duration_ms: 10,
                error: None,
            },
        );

        let report = MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 1,
            successful_scans: 1,
            failed_scans: 0,
            total_duration_ms: 10,
            inconsistencies: Vec::new(),
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("F".to_string(), 0),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
        };

        let json = generate_multi_ip_json(&report, true).expect("test assertion should succeed");
        assert!(json.contains("example.com"));

        let path = temp_file_path(".multi.json");
        write_multi_ip_json_file(&report, path.to_str().unwrap(), true)
            .expect("test assertion should succeed");
        let contents = std::fs::read_to_string(path).expect("test assertion should succeed");
        assert!(contents.contains("example.com"));
    }

    #[test]
    fn test_multi_ip_json_is_stable_for_map_insertion_order() {
        let report_a = {
            let target = Target::with_ips(
                "example.com".to_string(),
                443,
                vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
            )
            .expect("test assertion should succeed");

            let ip1: IpAddr = "192.0.2.1".parse().unwrap();
            let ip2: IpAddr = "192.0.2.2".parse().unwrap();
            let mut per_ip_results = HashMap::new();
            per_ip_results.insert(
                ip1,
                SingleIpScanResult {
                    ip: ip1,
                    scan_result: ScanResults::default(),
                    scan_duration_ms: 10,
                    error: None,
                },
            );
            per_ip_results.insert(
                ip2,
                SingleIpScanResult {
                    ip: ip2,
                    scan_result: ScanResults::default(),
                    scan_duration_ms: 20,
                    error: None,
                },
            );

            let mut fingerprints = HashMap::new();
            fingerprints.insert(ip1, "aaa111".to_string());
            fingerprints.insert(ip2, "bbb222".to_string());

            MultiIpScanReport {
                target,
                per_ip_results,
                total_ips: 2,
                successful_scans: 2,
                failed_scans: 0,
                total_duration_ms: 30,
                inconsistencies: vec![Inconsistency {
                    inconsistency_type: InconsistencyType::Certificates,
                    severity: Severity::High,
                    description: "certs differ".to_string(),
                    ips_affected: vec![ip1, ip2],
                    details: InconsistencyDetails::Certificates { fingerprints },
                }],
                aggregated: AggregatedScanResult {
                    protocols: Vec::new(),
                    ciphers: HashMap::new(),
                    grade: ("F".to_string(), 0),
                    certificate_info: None,
                    certificate_consistent: true,
                    inconsistencies: Vec::new(),
                    alpn_protocols: Vec::new(),
                    session_resumption_caching: Some(false),
                    session_resumption_tickets: Some(false),
                },
            }
        };

        let report_b = {
            let target = Target::with_ips(
                "example.com".to_string(),
                443,
                vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
            )
            .expect("test assertion should succeed");

            let ip1: IpAddr = "192.0.2.1".parse().unwrap();
            let ip2: IpAddr = "192.0.2.2".parse().unwrap();
            let mut per_ip_results = HashMap::new();
            per_ip_results.insert(
                ip2,
                SingleIpScanResult {
                    ip: ip2,
                    scan_result: ScanResults::default(),
                    scan_duration_ms: 20,
                    error: None,
                },
            );
            per_ip_results.insert(
                ip1,
                SingleIpScanResult {
                    ip: ip1,
                    scan_result: ScanResults::default(),
                    scan_duration_ms: 10,
                    error: None,
                },
            );

            let mut fingerprints = HashMap::new();
            fingerprints.insert(ip2, "bbb222".to_string());
            fingerprints.insert(ip1, "aaa111".to_string());

            MultiIpScanReport {
                target,
                per_ip_results,
                total_ips: 2,
                successful_scans: 2,
                failed_scans: 0,
                total_duration_ms: 30,
                inconsistencies: vec![Inconsistency {
                    inconsistency_type: InconsistencyType::Certificates,
                    severity: Severity::High,
                    description: "certs differ".to_string(),
                    ips_affected: vec![ip1, ip2],
                    details: InconsistencyDetails::Certificates { fingerprints },
                }],
                aggregated: AggregatedScanResult {
                    protocols: Vec::new(),
                    ciphers: HashMap::new(),
                    grade: ("F".to_string(), 0),
                    certificate_info: None,
                    certificate_consistent: true,
                    inconsistencies: Vec::new(),
                    alpn_protocols: Vec::new(),
                    session_resumption_caching: Some(false),
                    session_resumption_tickets: Some(false),
                },
            }
        };

        assert_eq!(
            generate_multi_ip_json(&report_a, true).expect("test assertion should succeed"),
            generate_multi_ip_json(&report_b, true).expect("test assertion should succeed")
        );
    }

    #[test]
    fn test_multi_ip_json_is_stable_for_displayed_inconsistencies() {
        let build_report = |reverse: bool| {
            let target = Target::with_ips(
                "example.com".to_string(),
                443,
                vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
            )
            .expect("test assertion should succeed");

            let ip1: IpAddr = "192.0.2.1".parse().unwrap();
            let ip2: IpAddr = "192.0.2.2".parse().unwrap();
            let mut per_ip_results = HashMap::new();
            if reverse {
                per_ip_results.insert(
                    ip2,
                    SingleIpScanResult {
                        ip: ip2,
                        scan_result: ScanResults::default(),
                        scan_duration_ms: 20,
                        error: None,
                    },
                );
                per_ip_results.insert(
                    ip1,
                    SingleIpScanResult {
                        ip: ip1,
                        scan_result: ScanResults::default(),
                        scan_duration_ms: 10,
                        error: None,
                    },
                );
            } else {
                per_ip_results.insert(
                    ip1,
                    SingleIpScanResult {
                        ip: ip1,
                        scan_result: ScanResults::default(),
                        scan_duration_ms: 10,
                        error: None,
                    },
                );
                per_ip_results.insert(
                    ip2,
                    SingleIpScanResult {
                        ip: ip2,
                        scan_result: ScanResults::default(),
                        scan_duration_ms: 20,
                        error: None,
                    },
                );
            }

            let mut fingerprints = HashMap::new();
            if reverse {
                fingerprints.insert(ip2, "bbb222".to_string());
                fingerprints.insert(ip1, "aaa111".to_string());
            } else {
                fingerprints.insert(ip1, "aaa111".to_string());
                fingerprints.insert(ip2, "bbb222".to_string());
            }

            MultiIpScanReport {
                target,
                per_ip_results,
                total_ips: 2,
                successful_scans: 2,
                failed_scans: 0,
                total_duration_ms: 30,
                inconsistencies: vec![Inconsistency {
                    inconsistency_type: InconsistencyType::Certificates,
                    severity: Severity::High,
                    description: "certs differ".to_string(),
                    ips_affected: vec![ip1, ip2],
                    details: InconsistencyDetails::Certificates { fingerprints },
                }],
                aggregated: AggregatedScanResult {
                    protocols: Vec::new(),
                    ciphers: HashMap::new(),
                    grade: ("F".to_string(), 0),
                    certificate_info: None,
                    certificate_consistent: true,
                    inconsistencies: Vec::new(),
                    alpn_protocols: Vec::new(),
                    session_resumption_caching: Some(false),
                    session_resumption_tickets: Some(false),
                },
            }
        };

        let json_a = generate_multi_ip_json(&build_report(false), true).unwrap();
        let json_b = generate_multi_ip_json(&build_report(true), true).unwrap();
        assert_eq!(json_a, json_b);
    }

    #[test]
    fn test_multi_ip_json_compact_has_no_newlines() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .expect("test assertion should succeed");

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 1,
            successful_scans: 0,
            failed_scans: 1,
            total_duration_ms: 1,
            inconsistencies: Vec::new(),
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("F".to_string(), 0),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
        };

        let json = generate_multi_ip_json(&report, false).expect("test assertion should succeed");
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_write_multi_ip_json_compact_file_has_no_newlines() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .expect("test assertion should succeed");

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 1,
            successful_scans: 0,
            failed_scans: 1,
            total_duration_ms: 1,
            inconsistencies: Vec::new(),
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("F".to_string(), 0),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
        };

        let path = temp_file_path(".multi.compact.json");
        write_multi_ip_json_file(&report, path.to_str().unwrap(), false)
            .expect("test assertion should succeed");
        let contents = std::fs::read_to_string(path).expect("test assertion should succeed");
        assert!(!contents.contains('\n'));
    }

    #[test]
    fn test_json_output_contains_target_field() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 42,
            ..Default::default()
        };

        let json = generate_json(&results, false).expect("test assertion should succeed");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json should parse");
        assert_eq!(
            value.get("target").and_then(|v| v.as_str()),
            Some("example.com:443")
        );
    }
}
