// CSV Output Module

use crate::Result;
use crate::scanner::ScanResults;
use csv::Writer;

/// Generate CSV output from scan results
/// Produces multiple CSV tables: protocols, vulnerabilities, and summary
pub fn generate_csv(results: &ScanResults) -> Result<String> {
    let mut output = String::new();

    // Summary
    output.push_str("=== SCAN SUMMARY ===\n");
    output.push_str("Target,Scan Time (ms),Protocols Tested,Vulnerabilities Tested\n");
    output.push_str(&format!(
        "{},{},{},{}\n",
        results.target,
        results.scan_time_ms,
        results.protocols.len(),
        results.vulnerabilities.len()
    ));
    output.push('\n');

    // Protocols
    output.push_str("=== PROTOCOLS ===\n");
    output.push_str("Protocol,Supported,Deprecated\n");
    for protocol in &results.protocols {
        output.push_str(&format!(
            "{},{},{}\n",
            protocol.protocol,
            protocol.supported,
            protocol.protocol.is_deprecated()
        ));
    }
    output.push('\n');

    // Vulnerabilities
    output.push_str("=== VULNERABILITIES ===\n");
    output.push_str("Type,Status,Severity,CVE,Details\n");
    for vuln in &results.vulnerabilities {
        output.push_str(&format!(
            "{:?},{},{:?},{},{}\n",
            vuln.vuln_type,
            vuln.status_csv_value(),
            vuln.severity,
            vuln.cve.as_deref().unwrap_or("N/A"),
            vuln.details.replace(',', ";").replace('\n', " ")
        ));
    }
    output.push('\n');

    // HTTP Headers Issues (if available)
    if let Some(headers) = results.http_headers() {
        output.push_str("=== HTTP SECURITY HEADERS ===\n");
        output.push_str("Grade,Score\n");
        output.push_str(&format!("{:?},{}\n", headers.grade, headers.score));
        output.push('\n');

        if !headers.issues.is_empty() {
            output.push_str("=== HEADER ISSUES ===\n");
            output.push_str("Header,Type,Severity,Description,Recommendation\n");
            for issue in &headers.issues {
                output.push_str(&format!(
                    "{},{:?},{:?},{},{}\n",
                    issue.header_name,
                    issue.issue_type,
                    issue.severity,
                    issue.description.replace(',', ";"),
                    issue.recommendation.replace(',', ";")
                ));
            }
            output.push('\n');
        }

        // Advanced Header Analysis
        if let Some(hsts) = &headers.hsts_analysis {
            output.push_str("=== HSTS ANALYSIS ===\n");
            output.push_str("Enabled,Grade,Max-Age,IncludeSubDomains,Preload,Details\n");
            output.push_str(&format!(
                "{},{:?},{},{},{},{}\n",
                hsts.enabled,
                hsts.grade,
                hsts.max_age.unwrap_or(0),
                hsts.include_subdomains,
                hsts.preload,
                hsts.details.replace(',', ";")
            ));
            output.push('\n');
        }

        if let Some(cookies) = &headers.cookie_analysis {
            output.push_str("=== COOKIE SECURITY ===\n");
            output.push_str(
                "Total Cookies,Secure Count,HttpOnly Count,SameSite Count,Insecure Count,Grade\n",
            );
            output.push_str(&format!(
                "{},{},{},{},{},{:?}\n",
                cookies.cookies.len(),
                cookies.secure_count,
                cookies.httponly_count,
                cookies.samesite_count,
                cookies.insecure_count,
                cookies.grade
            ));
            output.push('\n');

            if !cookies.cookies.is_empty() {
                output.push_str("=== COOKIE DETAILS ===\n");
                output.push_str("Name,Secure,HttpOnly,SameSite,Domain,Path\n");
                for cookie in &cookies.cookies {
                    output.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        cookie.name,
                        cookie.secure,
                        cookie.httponly,
                        cookie.samesite.as_deref().unwrap_or("N/A"),
                        cookie.domain.as_deref().unwrap_or("N/A"),
                        cookie.path.as_deref().unwrap_or("N/A")
                    ));
                }
                output.push('\n');
            }
        }

        if let Some(datetime) = &headers.datetime_check {
            output.push_str("=== DATE/TIME CHECK ===\n");
            output.push_str("Server Date,Synchronized,Skew (seconds),Details\n");
            output.push_str(&format!(
                "{},{},{},{}\n",
                datetime.server_date.as_deref().unwrap_or("N/A"),
                datetime.synchronized,
                datetime.skew_seconds.unwrap_or(0),
                datetime.details.replace(',', ";")
            ));
            output.push('\n');
        }

        if let Some(banners) = &headers.banner_detection {
            output.push_str("=== SERVER BANNERS ===\n");
            output.push_str("Server,X-Powered-By,Application,Version Exposed,Grade\n");
            output.push_str(&format!(
                "{},{},{},{},{:?}\n",
                banners.server.as_deref().unwrap_or("N/A"),
                banners.powered_by.as_deref().unwrap_or("N/A"),
                banners.application.as_deref().unwrap_or("N/A"),
                banners.version_exposed,
                banners.grade
            ));
            output.push('\n');
        }

        if let Some(proxy) = &headers.reverse_proxy_detection
            && proxy.detected
        {
            output.push_str("=== REVERSE PROXY DETECTION ===\n");
            output
                .push_str("Detected,Type,Via Header,X-Forwarded-For,X-Real-IP,X-Forwarded-Proto\n");
            output.push_str(&format!(
                "{},{},{},{},{},{}\n",
                proxy.detected,
                proxy.proxy_type.as_deref().unwrap_or("N/A"),
                proxy.via_header.as_deref().unwrap_or("N/A"),
                proxy.x_forwarded_for,
                proxy.x_real_ip,
                proxy.x_forwarded_proto
            ));
            output.push('\n');
        }
    }

    // Rating (if available)
    if let Some(rating) = results.ssl_rating() {
        output.push_str("=== SSL LABS RATING ===\n");
        output.push_str("Grade,Overall Score,Certificate Score,Protocol Score,Key Exchange Score,Cipher Strength Score\n");
        output.push_str(&format!(
            "{},{},{},{},{},{}\n",
            rating.grade,
            rating.score,
            rating.certificate_score,
            rating.protocol_score,
            rating.key_exchange_score,
            rating.cipher_strength_score
        ));
        output.push('\n');
    }

    // Client Simulations (if available)
    if let Some(clients) = results.client_simulations() {
        output.push_str("=== CLIENT COMPATIBILITY ===\n");
        output.push_str("Client,Success,Protocol,Cipher,Handshake Time (ms)\n");
        for client in clients {
            output.push_str(&format!(
                "{},{},{},{},{}\n",
                client.client_name,
                client.success,
                client
                    .protocol
                    .as_ref()
                    .map(|p| format!("{}", p))
                    .unwrap_or_else(|| "N/A".to_string()),
                client.cipher.as_ref().unwrap_or(&"N/A".to_string()),
                client.handshake_time_ms.unwrap_or(0)
            ));
        }
        output.push('\n');
    }

    Ok(output)
}

/// Write CSV to file
pub fn write_csv_file(results: &ScanResults, path: &str) -> Result<()> {
    let csv = generate_csv(results)?;
    std::fs::write(path, csv)?;
    Ok(())
}

/// Generate CSV for vulnerabilities only (traditional format)
pub fn generate_vulnerabilities_csv(results: &ScanResults) -> Result<String> {
    let mut wtr = Writer::from_writer(vec![]);

    // Write header
    wtr.write_record(["Type", "Severity", "Status", "CVE", "Details"])?;

    // Write data
    for vuln in &results.vulnerabilities {
        wtr.write_record(&[
            format!("{:?}", vuln.vuln_type),
            format!("{:?}", vuln.severity),
            vuln.status_csv_value().to_string(),
            vuln.cve.as_deref().unwrap_or("N/A").to_string(),
            vuln.details.replace(',', ";"),
        ])?;
    }

    let data = wtr.into_inner()?;
    Ok(String::from_utf8(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_sim::simulator::ClientSimulationResult;
    use crate::http::headers::{HeaderIssue, IssueSeverity, IssueType};
    use crate::http::headers_advanced::{
        BannerDetection, CookieAnalysis, CookieInfo, DateTimeCheck, Grade as HeaderGrade,
        HstsAnalysis, ReverseProxyDetection,
    };
    use crate::http::tester::{HeaderAnalysisResult, SecurityGrade};
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::rating::RatingResult;
    use crate::scanner::{AdvancedResults, HttpResults, RatingResults};
    use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};
    use std::collections::HashMap;

    #[test]
    fn test_csv_generation() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };

        let csv = generate_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("SCAN SUMMARY"));
        assert!(csv.contains("example.com"));
    }

    #[test]
    fn test_csv_generation_includes_protocols_section() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };

        let csv = generate_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("=== PROTOCOLS ==="));
    }

    #[test]
    fn test_csv_includes_optional_sections() {
        let mut results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1500,
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                preferred: true,
                ciphers_count: 3,
                handshake_time_ms: Some(45),
                heartbeat_enabled: Some(true),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(true),
                secure_renegotiation: Some(true),
            }],
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: false,
                inconclusive: false,
                details: "No issues, all good\nnewline".to_string(),
                cve: Some("CVE-2014-0160".to_string()),
                cwe: None,
                severity: Severity::Low,
            }],
            ..Default::default()
        };

        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=63072000; includeSubDomains; preload".to_string(),
        );

        let header_result = HeaderAnalysisResult {
            headers,
            issues: vec![HeaderIssue {
                header_name: "Content-Security-Policy".to_string(),
                severity: IssueSeverity::High,
                issue_type: IssueType::Missing,
                description: "CSP missing".to_string(),
                recommendation: "Add CSP".to_string(),
                preload_status: None,
            }],
            score: 75,
            grade: SecurityGrade::B,
            hsts_analysis: Some(HstsAnalysis {
                enabled: true,
                max_age: Some(63_072_000),
                include_subdomains: true,
                preload: true,
                details: "Strong policy".to_string(),
                grade: HeaderGrade::A,
            }),
            hpkp_analysis: None,
            cookie_analysis: Some(CookieAnalysis {
                cookies: vec![CookieInfo {
                    name: "session".to_string(),
                    secure: true,
                    httponly: true,
                    samesite: Some("Lax".to_string()),
                    domain: Some("example.com".to_string()),
                    path: Some("/".to_string()),
                    expires: None,
                }],
                secure_count: 1,
                httponly_count: 1,
                samesite_count: 1,
                insecure_count: 0,
                details: "Cookies are secure".to_string(),
                grade: HeaderGrade::A,
            }),
            datetime_check: Some(DateTimeCheck {
                server_date: Some("Tue, 01 Jan 2026 00:00:00 GMT".to_string()),
                skew_seconds: Some(5),
                synchronized: true,
                details: "Clock OK".to_string(),
            }),
            banner_detection: Some(BannerDetection {
                server: Some("nginx".to_string()),
                powered_by: Some("Rust".to_string()),
                application: Some("CipherRun".to_string()),
                framework: Some("axum".to_string()),
                version_exposed: true,
                details: "Version exposed".to_string(),
                grade: HeaderGrade::C,
            }),
            reverse_proxy_detection: Some(ReverseProxyDetection {
                detected: true,
                via_header: Some("1.1 proxy".to_string()),
                x_forwarded_for: true,
                x_real_ip: false,
                x_forwarded_proto: true,
                proxy_type: Some("CDN".to_string()),
                details: "Proxy detected".to_string(),
            }),
            http_status_code: Some(200),
            redirect_location: None,
            redirect_chain: Vec::new(),
            server_hostname: Some("example.com".to_string()),
        };

        results.http = Some(HttpResults {
            http_headers: Some(header_result),
        });

        results.rating = Some(RatingResults {
            ssl_rating: Some(RatingResult {
                grade: crate::rating::Grade::B,
                score: 80,
                certificate_score: 90,
                protocol_score: 85,
                key_exchange_score: 78,
                cipher_strength_score: 82,
                warnings: vec!["Warn".to_string()],
            }),
        });

        results.advanced = Some(AdvancedResults {
            client_simulations: Some(vec![ClientSimulationResult {
                client_name: "Firefox".to_string(),
                client_id: "fx".to_string(),
                success: true,
                protocol: Some(Protocol::TLS13),
                cipher: Some("TLS_AES_128_GCM_SHA256".to_string()),
                error: None,
                handshake_time_ms: Some(12),
                alpn: Some("h2".to_string()),
                key_exchange: Some("ECDHE".to_string()),
                forward_secrecy: true,
                certificate_type: Some("RSA 2048".to_string()),
            }]),
            ..Default::default()
        });

        let csv = generate_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("HTTP SECURITY HEADERS"));
        assert!(csv.contains("HSTS ANALYSIS"));
        assert!(csv.contains("COOKIE SECURITY"));
        assert!(csv.contains("DATE/TIME CHECK"));
        assert!(csv.contains("SERVER BANNERS"));
        assert!(csv.contains("REVERSE PROXY DETECTION"));
        assert!(csv.contains("SSL LABS RATING"));
        assert!(csv.contains("CLIENT COMPATIBILITY"));
    }

    #[test]
    fn test_csv_omits_reverse_proxy_section_when_not_detected() {
        let mut results = ScanResults::default();
        let header_result = HeaderAnalysisResult {
            headers: HashMap::new(),
            issues: Vec::new(),
            score: 100,
            grade: SecurityGrade::A,
            hsts_analysis: None,
            hpkp_analysis: None,
            cookie_analysis: None,
            datetime_check: None,
            banner_detection: None,
            reverse_proxy_detection: Some(ReverseProxyDetection {
                detected: false,
                via_header: None,
                x_forwarded_for: false,
                x_real_ip: false,
                x_forwarded_proto: false,
                proxy_type: None,
                details: "None".to_string(),
            }),
            http_status_code: None,
            redirect_location: None,
            redirect_chain: Vec::new(),
            server_hostname: None,
        };

        results.http = Some(HttpResults {
            http_headers: Some(header_result),
        });

        let csv = generate_csv(&results).expect("test assertion should succeed");
        assert!(!csv.contains("REVERSE PROXY DETECTION"));
    }

    #[test]
    fn test_write_csv_file_round_trip() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };
        let path = std::env::temp_dir().join("cipherrun_test_output.csv");
        write_csv_file(&results, path.to_str().unwrap()).expect("write should succeed");
        let contents = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(contents.contains("SCAN SUMMARY"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_vulnerabilities_csv() {
        let results = ScanResults::default();
        let csv = generate_vulnerabilities_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("Type,Severity,Status,CVE,Details"));
    }

    #[test]
    fn test_vulnerabilities_csv_sanitizes_commas() {
        let results = ScanResults {
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::DROWN,
                vulnerable: true,
                inconclusive: false,
                details: "Has,comma".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::High,
            }],
            ..Default::default()
        };
        let csv = generate_vulnerabilities_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("Has;comma"));
    }

    #[test]
    fn test_vulnerabilities_csv_includes_na_cve() {
        let results = ScanResults {
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::DROWN,
                vulnerable: false,
                inconclusive: false,
                details: "None".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Low,
            }],
            ..Default::default()
        };
        let csv = generate_vulnerabilities_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("N/A"));
    }

    #[test]
    fn test_generate_csv_replaces_newlines_in_details() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 10,
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: false,
                inconclusive: false,
                details: "line1\nline2".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Low,
            }],
            ..Default::default()
        };

        let csv = generate_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("line1 line2"));
        assert!(csv.contains("Heartbleed,not_vulnerable,Low"));
    }

    #[test]
    fn test_generate_csv_client_simulation_defaults_to_na() {
        let mut results = ScanResults::default();
        results.target = "example.com:443".to_string();
        results.scan_time_ms = 5;
        results.advanced = Some(AdvancedResults {
            client_simulations: Some(vec![ClientSimulationResult {
                client_name: "TestClient".to_string(),
                client_id: "tc".to_string(),
                success: false,
                protocol: None,
                cipher: None,
                error: Some("fail".to_string()),
                handshake_time_ms: None,
                alpn: None,
                key_exchange: None,
                forward_secrecy: false,
                certificate_type: None,
            }]),
            ..Default::default()
        });

        let csv = generate_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("CLIENT COMPATIBILITY"));
        assert!(csv.contains("N/A"));
    }

    #[test]
    fn test_vulnerabilities_csv_includes_type_name() {
        let results = ScanResults {
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "issue".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::High,
            }],
            ..Default::default()
        };

        let csv = generate_vulnerabilities_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("Heartbleed"));
    }

    #[test]
    fn test_generate_csv_preserves_inconclusive_status() {
        let results = ScanResults {
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::GREASE,
                vulnerable: false,
                inconclusive: true,
                details: "Heuristic only".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Info,
            }],
            ..Default::default()
        };

        let csv = generate_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("GREASE,inconclusive,Info"));
    }

    #[test]
    fn test_vulnerabilities_csv_empty_has_header() {
        let results = ScanResults::default();
        let csv = generate_vulnerabilities_csv(&results).expect("test assertion should succeed");
        assert!(csv.contains("Type,Severity,Status,CVE,Details"));
    }
}
