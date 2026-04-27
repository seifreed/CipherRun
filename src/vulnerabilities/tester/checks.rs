use super::{Protocol, Severity, VulnerabilityResult, VulnerabilityScanner, VulnerabilityType};
use crate::Result;

impl VulnerabilityScanner {
    pub async fn test_drown(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::drown::{DrownTester, Sslv2Status};

        let tester = DrownTester::new(self.target.clone());
        let result = tester.test().await?;
        let inconclusive = !result.vulnerable
            && matches!(result.sslv2_status, None | Some(Sslv2Status::Suspicious));

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::DROWN,
            vulnerable: result.vulnerable,
            inconclusive,
            details: result.details,
            cve: Some("CVE-2016-0800".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_rc4(&self) -> Result<VulnerabilityResult> {
        let summaries = self.collect_protocol_cipher_summaries().await?;
        Ok(super::cipher_checks::evaluate_rc4(
            summaries
                .iter()
                .map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub async fn test_null_ciphers(&self) -> Result<VulnerabilityResult> {
        let summaries = self.collect_protocol_cipher_summaries().await?;
        Ok(super::cipher_checks::evaluate_null(
            summaries
                .iter()
                .map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub async fn test_export_ciphers(&self) -> Result<VulnerabilityResult> {
        let summaries = self.collect_protocol_cipher_summaries().await?;
        Ok(super::cipher_checks::evaluate_export(
            summaries
                .iter()
                .map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub async fn test_poodle_ssl(&self) -> Result<VulnerabilityResult> {
        let protocol_result = self.protocol_tester.test_protocol(Protocol::SSLv3).await?;

        if !protocol_result.supported && !self.target_accepts_tcp().await? {
            return Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::POODLE,
                vulnerable: false,
                inconclusive: true,
                details: "POODLE SSL test inconclusive - target did not accept TCP connection"
                    .to_string(),
                cve: Some("CVE-2014-3566".to_string()),
                cwe: Some("CWE-310".to_string()),
                severity: Severity::Info,
            });
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::POODLE,
            vulnerable: protocol_result.supported,
            inconclusive: false,
            details: if protocol_result.supported {
                "Server supports SSLv3, vulnerable to POODLE attack".to_string()
            } else {
                "Server does not support SSLv3".to_string()
            },
            cve: Some("CVE-2014-3566".to_string()),
            cwe: Some("CWE-310".to_string()),
            severity: if protocol_result.supported {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_poodle_variants(&self) -> Result<Vec<VulnerabilityResult>> {
        use crate::vulnerabilities::poodle::{PoodleTester, PoodleVariant};

        let tester = PoodleTester::new(&self.target);
        let test_result = tester.test_all_variants().await?;

        Ok(test_result
            .variants
            .into_iter()
            .filter_map(|variant_result| {
                let vuln_type = match variant_result.variant {
                    PoodleVariant::ZombiePoodle => VulnerabilityType::ZombiePoodle,
                    PoodleVariant::GoldenDoodle => VulnerabilityType::GoldenDoodle,
                    PoodleVariant::SleepingPoodle => VulnerabilityType::SleepingPoodle,
                    PoodleVariant::OpenSsl0Length => VulnerabilityType::OpenSsl0Length,
                    PoodleVariant::SslV3 | PoodleVariant::Tls => return None,
                };

                let severity = if variant_result.vulnerable {
                    match variant_result.variant {
                        PoodleVariant::ZombiePoodle | PoodleVariant::GoldenDoodle => Severity::High,
                        PoodleVariant::SleepingPoodle => Severity::Medium,
                        PoodleVariant::OpenSsl0Length => Severity::High,
                        PoodleVariant::SslV3 | PoodleVariant::Tls => Severity::Info,
                    }
                } else {
                    Severity::Info
                };

                Some(VulnerabilityResult {
                    vuln_type,
                    vulnerable: variant_result.vulnerable,
                    // V3 fix: propagate the explicit `inconclusive` flag instead of
                    // sniffing the details string for the substring "inconclusive".
                    // The string check missed variant wording like "Insufficient
                    // timing samples" which would otherwise classify a failed
                    // probe as confirmed-not-vulnerable.
                    inconclusive: variant_result.inconclusive,
                    details: variant_result.details,
                    cve: Some(variant_result.variant.cve().to_string()),
                    cwe: Some("CWE-310".to_string()),
                    severity,
                })
            })
            .collect())
    }

    pub async fn test_beast(&self) -> Result<VulnerabilityResult> {
        // BEAST vulnerability affects both TLS 1.0 and SSL 3.0 with CBC ciphers
        // Test both protocols for comprehensive vulnerability detection
        let tls10_result = self.protocol_tester.test_protocol(Protocol::TLS10).await?;
        let ssl3_result = self.protocol_tester.test_protocol(Protocol::SSLv3).await?;

        let tls10_supported = tls10_result.supported;
        let ssl3_supported = ssl3_result.supported;

        if !tls10_supported && !ssl3_supported {
            if !self.target_accepts_tcp().await? {
                return Ok(VulnerabilityResult {
                    vuln_type: VulnerabilityType::BEAST,
                    vulnerable: false,
                    inconclusive: true,
                    details: "BEAST test inconclusive - target did not accept TCP connection"
                        .to_string(),
                    cve: Some("CVE-2011-3389".to_string()),
                    cwe: Some("CWE-326".to_string()),
                    severity: Severity::Info,
                });
            }

            return Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::BEAST,
                vulnerable: false,
                inconclusive: false,
                details: "Server does not support TLS 1.0 or SSL 3.0".to_string(),
                cve: Some("CVE-2011-3389".to_string()),
                cwe: Some("CWE-326".to_string()),
                severity: Severity::Info,
            });
        }

        // Get cipher summaries for each supported protocol
        let tls10_summary = if tls10_supported {
            Some(
                self.cipher_tester
                    .test_protocol_ciphers(Protocol::TLS10)
                    .await?,
            )
        } else {
            None
        };

        let ssl3_summary = if ssl3_supported {
            Some(
                self.cipher_tester
                    .test_protocol_ciphers(Protocol::SSLv3)
                    .await?,
            )
        } else {
            None
        };

        let mut result =
            super::cipher_checks::evaluate_beast(tls10_summary.as_ref(), ssl3_summary.as_ref());

        if !result.vulnerable {
            let has_legacy_cipher_evidence = [tls10_summary.as_ref(), ssl3_summary.as_ref()]
                .into_iter()
                .flatten()
                .any(super::cipher_checks::summary_has_cipher_evidence);

            if !has_legacy_cipher_evidence {
                result.inconclusive = true;
                result.details =
                    "BEAST test inconclusive - no successful TLS 1.0/SSL 3.0 cipher enumeration results"
                        .to_string();
            }
        }

        Ok(result)
    }

    pub async fn test_renegotiation(&self) -> Result<VulnerabilityResult> {
        use crate::protocols::renegotiation::RenegotiationTester;

        let tester = RenegotiationTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Renegotiation,
            vulnerable: result.vulnerable,
            inconclusive: result.needs_verification,
            details: result.details,
            cve: Some("CVE-2009-3555".to_string()),
            cwe: Some("CWE-310".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_tls_fallback(&self) -> Result<VulnerabilityResult> {
        use crate::protocols::fallback_scsv::FallbackScsvTester;

        let mut tester = FallbackScsvTester::new(&self.target).with_sni(self.sni_hostname.clone());
        let result = tester.test().await?;

        let severity = if result.vulnerable {
            if result.has_tls13_or_higher {
                Severity::Medium
            } else {
                Severity::High
            }
        } else {
            Severity::Info
        };

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::TLSFallback,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2014-8730".to_string()),
            cwe: Some("CWE-757".to_string()),
            severity,
        })
    }

    pub async fn test_compression(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::crime::CrimeTester;

        let tester = CrimeTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::CRIME,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2012-4929".to_string()),
            cwe: Some("CWE-310".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_heartbleed(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::heartbleed::HeartbleedTester;

        let tester = HeartbleedTester::new(&self.target).with_sni(self.sni_hostname.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: result.vulnerable,
            // Mark as inconclusive if the test couldn't be performed
            inconclusive: !result.tested,
            details: result.details,
            cve: Some("CVE-2014-0160".to_string()),
            cwe: Some("CWE-119".to_string()),
            severity: if result.vulnerable {
                Severity::Critical
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_ccs(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::ccs::CcsInjectionTester;

        let tester = CcsInjectionTester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::CCSInjection,
            vulnerable: result.vulnerable,
            inconclusive: result.status.is_inconclusive(),
            details: result.details,
            cve: Some("CVE-2014-0224".to_string()),
            cwe: Some("CWE-310".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_ticketbleed(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::ticketbleed::TicketbleedTester;

        let tester = TicketbleedTester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Ticketbleed,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2016-9244".to_string()),
            cwe: Some("CWE-200".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_robot(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::robot::{RobotStatus, RobotTester};

        let tester = RobotTester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::ROBOT,
            vulnerable: result.vulnerable,
            inconclusive: matches!(result.status, RobotStatus::Inconclusive),
            details: result.details,
            cve: Some("CVE-2017-17382".to_string()),
            cwe: Some("CWE-203".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_breach(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::breach::BreachTester;

        let tester = BreachTester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::BREACH,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2013-3587".to_string()),
            cwe: Some("CWE-200".to_string()),
            severity: if result.vulnerable {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_sweet32(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::sweet32::Sweet32Tester;

        let tester = Sweet32Tester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::SWEET32,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2016-2183".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if result.vulnerable {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_freak(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::freak::FreakTester;

        let tester = FreakTester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::FREAK,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2015-0204".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_logjam(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::logjam::LogjamTester;

        let tester = LogjamTester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::LOGJAM,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2015-4000".to_string()),
            cwe: Some("CWE-326".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_lucky13(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::lucky13::Lucky13Tester;

        let tester = Lucky13Tester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::LUCKY13,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive || result.partially_vulnerable,
            details: result.details,
            cve: Some("CVE-2013-0169".to_string()),
            cwe: Some("CWE-208".to_string()),
            severity: if result.vulnerable {
                Severity::Medium
            } else if result.partially_vulnerable {
                Severity::Low
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_early_data(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::early_data::EarlyDataTester;

        let tester = EarlyDataTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::EarlyDataReplay,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: None,
            cwe: Some("CWE-294".to_string()),
            severity: if result.vulnerable {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_padding_oracle_2016(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::padding_oracle_2016::PaddingOracle2016Tester;

        let tester = PaddingOracle2016Tester::new(&self.target);
        let result = tester.test().await?;

        if !result.cbc_supported && !self.target_accepts_tcp().await? {
            return Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::PaddingOracle2016,
                vulnerable: false,
                inconclusive: true,
                details: "CVE-2016-2107 test inconclusive - target did not accept TCP connection"
                    .to_string(),
                cve: Some("CVE-2016-2107".to_string()),
                cwe: Some("CWE-203".to_string()),
                severity: Severity::Info,
            });
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::PaddingOracle2016,
            vulnerable: result.vulnerable,
            inconclusive: result.cbc_supported && !result.vulnerable,
            details: result.details,
            cve: Some("CVE-2016-2107".to_string()),
            cwe: Some("CWE-203".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_opossum(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::opossum::OpossumTester;

        let tester = OpossumTester::new(self.target.clone());
        let result = tester.test().await?;

        // V2: severity must track `vulnerable`, not `inconclusive`. The Opossum
        // tester always reports `vulnerable=false` (remote detection is not
        // reliable), so the effective verdict is Info in both the inconclusive
        // and not-vulnerable cases — the `details` string conveys the uncertainty.
        let severity = if result.vulnerable {
            Severity::Medium
        } else {
            Severity::Info
        };
        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Opossum,
            vulnerable: result.vulnerable,
            inconclusive: result.inconclusive,
            details: result.details,
            cve: Some("CVE-2022-0778".to_string()),
            cwe: Some("CWE-835".to_string()),
            severity,
        })
    }

    pub async fn test_grease(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::grease::GreaseTester;

        let tester = GreaseTester::new(self.target.clone()).with_sni(self.sni_hostname.clone());
        let result = tester.test().await?;

        let details = if result.details.is_empty() && result.issues.is_empty() {
            "No GREASE issues observed".to_string()
        } else {
            let mut parts = result.details;
            parts.extend(result.issues);
            parts.join("; ")
        };

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::GREASE,
            vulnerable: !result.inconclusive && !result.tolerates_grease,
            inconclusive: result.inconclusive || !result.direct_grease_test_performed,
            details,
            cve: None,
            cwe: Some("CWE-436".to_string()),
            severity: Severity::Info,
        })
    }

    async fn collect_protocol_cipher_summaries(
        &self,
    ) -> Result<Vec<(Protocol, crate::ciphers::tester::ProtocolCipherSummary)>> {
        let mut summaries = Vec::new();
        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let cipher_summary = self.cipher_tester.test_protocol_ciphers(protocol).await?;
            summaries.push((protocol, cipher_summary));
        }

        Ok(summaries)
    }

    async fn target_accepts_tcp(&self) -> Result<bool> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        Ok(crate::utils::network::connect_with_timeout(
            addr,
            crate::constants::DEFAULT_CONNECT_TIMEOUT,
            None,
        )
        .await
        .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphers::CipherSuite;
    use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
    use crate::protocols::Protocol;
    use crate::utils::network::Target;
    use crate::vulnerabilities::{Severity, VulnerabilityType};
    use std::net::TcpListener;

    fn make_cipher(encryption: &str, bits: u16, export: bool) -> CipherSuite {
        CipherSuite {
            hexcode: "002F".to_string(),
            openssl_name: format!("TEST-{}", encryption),
            iana_name: format!("TLS_TEST_{}", encryption),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "RSA".to_string(),
            authentication: "RSA".to_string(),
            encryption: encryption.to_string(),
            mac: "SHA256".to_string(),
            bits,
            export,
        }
    }

    fn empty_summary(protocol: Protocol) -> ProtocolCipherSummary {
        ProtocolCipherSummary {
            protocol,
            supported_ciphers: Vec::new(),
            server_ordered: false,
            server_preference: Vec::new(),
            preferred_cipher: None,
            counts: CipherCounts::default(),
            avg_handshake_time_ms: None,
        }
    }

    fn summary_with_ciphers(
        protocol: Protocol,
        ciphers: Vec<CipherSuite>,
        counts: CipherCounts,
    ) -> ProtocolCipherSummary {
        ProtocolCipherSummary {
            protocol,
            supported_ciphers: ciphers,
            server_ordered: false,
            server_preference: Vec::new(),
            preferred_cipher: None,
            counts,
            avg_handshake_time_ms: None,
        }
    }

    // --- test_drown ---

    #[tokio::test]
    async fn test_drown_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let scanner = super::VulnerabilityScanner::new(target);
        let result = scanner.test_drown().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean DROWN pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    // --- test_poodle_ssl ---

    #[tokio::test]
    async fn test_poodle_ssl_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let scanner = super::VulnerabilityScanner::new(target);
        let result = scanner.test_poodle_ssl().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean POODLE pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    // --- test_renegotiation ---

    #[tokio::test]
    async fn test_renegotiation_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let scanner = super::VulnerabilityScanner::new(target);
        let result = scanner.test_renegotiation().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean renegotiation pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("unclear"));
    }

    // --- test_padding_oracle_2016 ---

    #[tokio::test]
    async fn test_padding_oracle_2016_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let scanner = super::VulnerabilityScanner::new(target);
        let result = scanner.test_padding_oracle_2016().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean padding-oracle pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    // --- test_early_data ---

    #[tokio::test]
    async fn test_early_data_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let scanner = super::VulnerabilityScanner::new(target);
        let result = scanner.test_early_data().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean Early Data pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    // --- test_lucky13 ---

    #[tokio::test]
    async fn test_lucky13_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let scanner = super::VulnerabilityScanner::new(target);
        let result = scanner.test_lucky13().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean Lucky13 pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    // --- evaluate_rc4 ---

    #[test]
    fn evaluate_rc4_empty_summaries() {
        let result = super::super::cipher_checks::evaluate_rc4(std::iter::empty());
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert_eq!(result.vuln_type, VulnerabilityType::RC4);
        assert_eq!(result.severity, Severity::Info);
    }

    #[test]
    fn evaluate_rc4_no_rc4_ciphers() {
        let ciphers = vec![make_cipher("AES128-GCM", 128, false)];
        let summary = summary_with_ciphers(
            Protocol::TLS12,
            ciphers,
            CipherCounts {
                total: 1,
                high_strength: 1,
                aead: 1,
                ..Default::default()
            },
        );
        let result =
            super::super::cipher_checks::evaluate_rc4(std::iter::once((Protocol::TLS12, &summary)));
        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
    }

    #[test]
    fn evaluate_rc4_with_rc4_cipher() {
        let ciphers = vec![make_cipher("RC4-SHA", 128, false)];
        let summary = summary_with_ciphers(Protocol::TLS12, ciphers, CipherCounts::default());
        let result =
            super::super::cipher_checks::evaluate_rc4(std::iter::once((Protocol::TLS12, &summary)));
        assert!(result.vulnerable);
        assert_eq!(result.severity, Severity::Medium);
        assert!(result.details.contains("RC4"));
    }

    // --- evaluate_null ---

    #[test]
    fn evaluate_null_empty_summaries() {
        let result = super::super::cipher_checks::evaluate_null(std::iter::empty());
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert_eq!(result.vuln_type, VulnerabilityType::NullCipher);
    }

    #[test]
    fn evaluate_null_with_null_ciphers() {
        let counts = CipherCounts {
            total: 1,
            null_ciphers: 1,
            ..Default::default()
        };
        let summary = summary_with_ciphers(Protocol::TLS12, Vec::new(), counts);
        let result = super::super::cipher_checks::evaluate_null(std::iter::once((
            Protocol::TLS12,
            &summary,
        )));
        assert!(result.vulnerable);
        assert_eq!(result.severity, Severity::Critical);
    }

    #[test]
    fn evaluate_null_without_null_ciphers() {
        let ciphers = vec![make_cipher("AES128-GCM", 128, false)];
        let summary = summary_with_ciphers(
            Protocol::TLS12,
            ciphers,
            CipherCounts {
                total: 1,
                high_strength: 1,
                aead: 1,
                ..Default::default()
            },
        );
        let result = super::super::cipher_checks::evaluate_null(std::iter::once((
            Protocol::TLS12,
            &summary,
        )));
        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
    }

    // --- evaluate_export ---

    #[test]
    fn evaluate_export_empty_summaries() {
        let result = super::super::cipher_checks::evaluate_export(std::iter::empty());
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert_eq!(result.vuln_type, VulnerabilityType::FREAK);
    }

    #[test]
    fn evaluate_export_with_export_ciphers() {
        let counts = CipherCounts {
            total: 1,
            export_ciphers: 1,
            ..Default::default()
        };
        let summary = summary_with_ciphers(Protocol::TLS10, Vec::new(), counts);
        let result = super::super::cipher_checks::evaluate_export(std::iter::once((
            Protocol::TLS10,
            &summary,
        )));
        assert!(result.vulnerable);
        assert_eq!(result.severity, Severity::High);
    }

    // --- evaluate_beast ---

    #[test]
    fn evaluate_beast_no_summary() {
        let result = super::super::cipher_checks::evaluate_beast(None, None);
        assert!(!result.vulnerable);
        assert_eq!(result.vuln_type, VulnerabilityType::BEAST);
        assert_eq!(result.severity, Severity::Info);
    }

    #[tokio::test]
    async fn test_beast_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let scanner = super::VulnerabilityScanner::new(target);
        let result = scanner.test_beast().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean BEAST pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    #[test]
    fn evaluate_beast_with_tls10_cbc_ciphers() {
        let ciphers = vec![make_cipher("AES128-CBC", 128, false)];
        let summary = summary_with_ciphers(Protocol::TLS10, ciphers, CipherCounts::default());
        let result = super::super::cipher_checks::evaluate_beast(Some(&summary), None);
        assert!(result.vulnerable);
        assert_eq!(result.severity, Severity::Medium);
        assert!(result.details.contains("TLS 1.0"));
        assert!(result.details.contains("CBC"));
    }

    #[test]
    fn evaluate_beast_with_ssl3_cbc_ciphers() {
        let ciphers = vec![make_cipher("AES128-CBC", 128, false)];
        let summary = summary_with_ciphers(Protocol::SSLv3, ciphers, CipherCounts::default());
        let result = super::super::cipher_checks::evaluate_beast(None, Some(&summary));
        assert!(result.vulnerable);
        assert!(result.details.contains("SSL 3.0"));
    }

    #[test]
    fn evaluate_beast_with_both_protocols() {
        let tls10_ciphers = vec![make_cipher("AES128-CBC", 128, false)];
        let tls10_summary =
            summary_with_ciphers(Protocol::TLS10, tls10_ciphers, CipherCounts::default());
        let ssl3_ciphers = vec![make_cipher("AES256-CBC", 256, false)];
        let ssl3_summary =
            summary_with_ciphers(Protocol::SSLv3, ssl3_ciphers, CipherCounts::default());
        let result =
            super::super::cipher_checks::evaluate_beast(Some(&tls10_summary), Some(&ssl3_summary));
        assert!(result.vulnerable);
        assert!(result.details.contains("TLS 1.0"));
        assert!(result.details.contains("SSL 3.0"));
    }

    #[test]
    fn evaluate_beast_without_cbc_ciphers() {
        let ciphers = vec![make_cipher("AES128-GCM", 128, false)];
        let summary = summary_with_ciphers(Protocol::TLS10, ciphers, CipherCounts::default());
        let result = super::super::cipher_checks::evaluate_beast(Some(&summary), None);
        assert!(!result.vulnerable);
    }

    // --- evaluate across multiple protocols ---

    #[test]
    fn evaluate_rc4_across_multiple_protocols() {
        let s1 = empty_summary(Protocol::TLS10);
        let ciphers = vec![make_cipher("RC4-MD5", 128, false)];
        let s2 = summary_with_ciphers(Protocol::TLS12, ciphers, CipherCounts::default());
        let summaries = vec![(Protocol::TLS10, &s1), (Protocol::TLS12, &s2)];
        let result = super::super::cipher_checks::evaluate_rc4(summaries);
        assert!(result.vulnerable);
        assert!(result.details.contains("TLS 1.2"));
    }

    // --- VulnerabilityResult helper methods ---

    #[test]
    fn vulnerability_result_status_label_vulnerable() {
        let result = crate::vulnerabilities::VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: false,
            details: String::new(),
            cve: None,
            cwe: None,
            severity: Severity::Critical,
        };
        assert_eq!(result.status_label(), "Vulnerable");
        assert_eq!(result.status_csv_value(), "vulnerable");
    }

    #[test]
    fn vulnerability_result_status_label_not_vulnerable() {
        let result = crate::vulnerabilities::VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: false,
            inconclusive: false,
            details: String::new(),
            cve: None,
            cwe: None,
            severity: Severity::Info,
        };
        assert_eq!(result.status_label(), "Not Vulnerable");
        assert_eq!(result.status_csv_value(), "not_vulnerable");
    }

    #[test]
    fn vulnerability_result_status_label_inconclusive() {
        let result = crate::vulnerabilities::VulnerabilityResult {
            vuln_type: VulnerabilityType::ROBOT,
            vulnerable: false,
            inconclusive: true,
            details: String::new(),
            cve: None,
            cwe: None,
            severity: Severity::Info,
        };
        assert_eq!(result.status_label(), "Inconclusive");
        assert_eq!(result.status_csv_value(), "inconclusive");
    }
}
