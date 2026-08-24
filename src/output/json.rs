// JSON Output Module

use crate::Result;
use crate::scanner::ScanResults;
use crate::scanner::multi_ip::MultiIpScanReport;

fn serialize_json<T: serde::Serialize + ?Sized>(value: &T, pretty: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(value)?)
    } else {
        Ok(serde_json::to_string(value)?)
    }
}

/// Generate JSON output from scan results
pub fn generate_json(results: &ScanResults, pretty: bool) -> Result<String> {
    let mut value = serde_json::to_value(results)?;
    if let Some((ip, port, sni)) = single_ip_context(results) {
        enrich_finding_endpoints(&mut value, ip, port, &sni);
    }
    serialize_json(&value, pretty)
}

fn single_ip_context(results: &ScanResults) -> Option<(std::net::IpAddr, u16, String)> {
    let (host, embedded_port) = crate::utils::network::split_target_host_port(&results.target)
        .ok()
        .unwrap_or_else(|| (results.target.clone(), None));
    let ip = results
        .scan_metadata
        .scanned_ips
        .first()
        .map(|entry| entry.ip)
        .or_else(|| host.parse().ok())?;
    let port = embedded_port.unwrap_or(443);
    let sni = results.scan_metadata.sni_used.clone().unwrap_or(host);
    Some((ip, port, sni))
}

/// Generate JSON output from multi-IP scan report
pub fn generate_multi_ip_json(report: &MultiIpScanReport, pretty: bool) -> Result<String> {
    let mut value = serde_json::to_value(report)?;
    if let Some(per_ip_results) = value
        .get_mut("per_ip_results")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (ip, result) in &report.per_ip_results {
            let Some(scan_result) = per_ip_results
                .get_mut(&ip.to_string())
                .and_then(|result| result.get_mut("scan_result"))
            else {
                continue;
            };
            let sni = result
                .scan_result
                .scan_metadata
                .sni_used
                .as_deref()
                .unwrap_or(&report.target.hostname);
            enrich_finding_endpoints(scan_result, *ip, report.target.port, sni);
        }
    }
    serialize_json(&value, pretty)
}

fn enrich_finding_endpoints(
    scan_result: &mut serde_json::Value,
    ip: std::net::IpAddr,
    port: u16,
    sni: &str,
) {
    let Some(findings) = scan_result
        .get_mut("vulnerabilities")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for finding in findings {
        let Some(evidence) = finding
            .get_mut("evidence")
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        evidence.insert("affected_ip".to_string(), ip.to_string().into());
        evidence.insert("port".to_string(), port.into());
        evidence.insert("sni".to_string(), sni.into());
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
    use crate::scanner::inconsistency::{Inconsistency, InconsistencyDetails, InconsistencyType};
    use crate::scanner::multi_ip::MultiIpScanReport;
    use crate::scanner::test_support::{empty_aggregated_result, successful_ip_scan};
    use crate::utils::network::Target;
    use crate::utils::test_support::example_com_loopback_target;
    use crate::vulnerabilities::Severity;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn single_ip_target() -> Target {
        example_com_loopback_target(443)
    }

    fn two_ip_target() -> Target {
        Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
        )
        .expect("test assertion should succeed")
    }

    fn failed_multi_ip_report() -> MultiIpScanReport {
        MultiIpScanReport {
            target: single_ip_target(),
            per_ip_results: HashMap::new(),
            total_ips: 1,
            successful_scans: 0,
            failed_scans: 1,
            total_duration_ms: 1,
            inconsistencies: Vec::new(),
            aggregated: empty_aggregated_result(),
        }
    }

    #[test]
    fn test_json_generation() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };

        let json = generate_json(&results, false).expect("test assertion should succeed");
        assert!(json.contains("example.com"));
        assert!(!json.contains('\n'));

        let pretty_json = generate_json(&results, true).expect("test assertion should succeed");
        assert!(pretty_json.contains("example.com"));
        assert!(pretty_json.contains("\n")); // Check for pretty printing
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
        let target = single_ip_target();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut per_ip_results = HashMap::new();
        per_ip_results.insert(ip, successful_ip_scan(ip, ScanResults::default(), 10));

        let report = MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 1,
            successful_scans: 1,
            failed_scans: 0,
            total_duration_ms: 10,
            inconsistencies: Vec::new(),
            aggregated: empty_aggregated_result(),
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
    fn multi_ip_json_contextualizes_finding_evidence() {
        let target = single_ip_target();
        let ip = target.ip_addresses[0];
        let mut scan = ScanResults {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        scan.vulnerabilities
            .push(crate::vulnerabilities::VulnerabilityResult {
                vuln_type: crate::vulnerabilities::VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "confirmed".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Critical,
            });
        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::from([(ip, successful_ip_scan(ip, scan, 10))]),
            total_ips: 1,
            successful_scans: 1,
            failed_scans: 0,
            total_duration_ms: 10,
            inconsistencies: Vec::new(),
            aggregated: empty_aggregated_result(),
        };

        let value: serde_json::Value =
            serde_json::from_str(&generate_multi_ip_json(&report, false).unwrap()).unwrap();
        let evidence = &value["per_ip_results"][ip.to_string()]["scan_result"]["vulnerabilities"]
            [0]["evidence"];
        assert_eq!(evidence["affected_ip"], ip.to_string());
        assert_eq!(evidence["port"], 443);
        assert_eq!(evidence["sni"], "example.com");
    }

    #[test]
    fn single_ip_json_contextualizes_finding_evidence() {
        let mut results = ScanResults {
            target: "127.0.0.1:8443".to_string(),
            ..Default::default()
        };
        results
            .vulnerabilities
            .push(crate::vulnerabilities::VulnerabilityResult {
                vuln_type: crate::vulnerabilities::VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "confirmed".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Critical,
            });

        let value: serde_json::Value =
            serde_json::from_str(&generate_json(&results, false).unwrap()).unwrap();
        let evidence = &value["vulnerabilities"][0]["evidence"];
        assert_eq!(evidence["affected_ip"], "127.0.0.1");
        assert_eq!(evidence["port"], 8443);
        assert_eq!(evidence["sni"], "127.0.0.1");
    }

    #[test]
    fn test_multi_ip_json_is_stable_for_map_insertion_order() {
        let report_a = {
            let target = two_ip_target();

            let ip1: IpAddr = "192.0.2.1".parse().unwrap();
            let ip2: IpAddr = "192.0.2.2".parse().unwrap();
            let mut per_ip_results = HashMap::new();
            per_ip_results.insert(ip1, successful_ip_scan(ip1, ScanResults::default(), 10));
            per_ip_results.insert(ip2, successful_ip_scan(ip2, ScanResults::default(), 20));

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
                aggregated: empty_aggregated_result(),
            }
        };

        let report_b = {
            let target = two_ip_target();

            let ip1: IpAddr = "192.0.2.1".parse().unwrap();
            let ip2: IpAddr = "192.0.2.2".parse().unwrap();
            let mut per_ip_results = HashMap::new();
            per_ip_results.insert(ip2, successful_ip_scan(ip2, ScanResults::default(), 20));
            per_ip_results.insert(ip1, successful_ip_scan(ip1, ScanResults::default(), 10));

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
                aggregated: empty_aggregated_result(),
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
            let target = two_ip_target();

            let ip1: IpAddr = "192.0.2.1".parse().unwrap();
            let ip2: IpAddr = "192.0.2.2".parse().unwrap();
            let mut per_ip_results = HashMap::new();
            if reverse {
                per_ip_results.insert(ip2, successful_ip_scan(ip2, ScanResults::default(), 20));
                per_ip_results.insert(ip1, successful_ip_scan(ip1, ScanResults::default(), 10));
            } else {
                per_ip_results.insert(ip1, successful_ip_scan(ip1, ScanResults::default(), 10));
                per_ip_results.insert(ip2, successful_ip_scan(ip2, ScanResults::default(), 20));
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
                aggregated: empty_aggregated_result(),
            }
        };

        let json_a = generate_multi_ip_json(&build_report(false), true).unwrap();
        let json_b = generate_multi_ip_json(&build_report(true), true).unwrap();
        assert_eq!(json_a, json_b);
    }

    #[test]
    fn test_multi_ip_json_compact_has_no_newlines() {
        let report = failed_multi_ip_report();

        let json = generate_multi_ip_json(&report, false).expect("test assertion should succeed");
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_write_multi_ip_json_compact_file_has_no_newlines() {
        let report = failed_multi_ip_report();

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
