mod aggregation;
mod certificate;
mod multi_ip;

fn collect_scanned_ips(
    report: &crate::scanner::multi_ip::MultiIpScanReport,
) -> Vec<crate::utils::anycast::IpScanResult> {
    let mut per_ip_results: Vec<_> = report
        .per_ip_results
        .values()
        .map(|result| crate::utils::anycast::IpScanResult {
            ip: result.ip,
            results: result.scan_result.clone(),
            error: result.error.clone(),
        })
        .collect();
    per_ip_results.sort_by_key(|result| result.ip);
    per_ip_results
}

#[cfg(test)]
mod tests {
    use super::collect_scanned_ips;
    use crate::scanner::ScanResults;
    use crate::scanner::aggregation::AggregatedScanResult;
    use crate::scanner::inconsistency::SingleIpScanResult;
    use crate::scanner::multi_ip::MultiIpScanReport;
    use crate::utils::network::Target;
    use std::collections::HashMap;
    use std::net::IpAddr;

    #[test]
    fn test_collect_scanned_ips_sorts_by_ip() {
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();

        let target = Target::with_ips("example.com".to_string(), 443, vec![ip1, ip2]).unwrap();

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

        let report = MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 2,
            successful_scans: 2,
            failed_scans: 0,
            total_duration_ms: 30,
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

        let scanned_ips = collect_scanned_ips(&report);
        assert_eq!(scanned_ips[0].ip, ip1);
        assert_eq!(scanned_ips[1].ip, ip2);
    }
}
