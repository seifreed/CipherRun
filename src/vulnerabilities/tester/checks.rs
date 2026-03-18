use super::{Protocol, Severity, VulnerabilityResult, VulnerabilityScanner, VulnerabilityType};
use crate::Result;

impl VulnerabilityScanner {
    pub async fn test_drown(&self) -> Result<VulnerabilityResult> {
        let protocol_result = self.protocol_tester.test_protocol(Protocol::SSLv2).await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::DROWN,
            vulnerable: protocol_result.supported,
            inconclusive: false,
            details: if protocol_result.supported {
                "Server supports SSLv2, vulnerable to DROWN attack".to_string()
            } else {
                "Server does not support SSLv2".to_string()
            },
            cve: Some("CVE-2016-0800".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if protocol_result.supported {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_rc4(&self) -> Result<VulnerabilityResult> {
        let summaries = self.collect_protocol_cipher_summaries().await?;
        Ok(super::cipher_checks::evaluate_rc4(
            summaries.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub async fn test_3des(&self) -> Result<VulnerabilityResult> {
        let summaries = self.collect_protocol_cipher_summaries().await?;
        Ok(super::cipher_checks::evaluate_3des(
            summaries.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub async fn test_null_ciphers(&self) -> Result<VulnerabilityResult> {
        let summaries = self.collect_protocol_cipher_summaries().await?;
        Ok(super::cipher_checks::evaluate_null(
            summaries.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub async fn test_export_ciphers(&self) -> Result<VulnerabilityResult> {
        let summaries = self.collect_protocol_cipher_summaries().await?;
        Ok(super::cipher_checks::evaluate_export(
            summaries.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub async fn test_poodle_ssl(&self) -> Result<VulnerabilityResult> {
        let protocol_result = self.protocol_tester.test_protocol(Protocol::SSLv3).await?;

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
                    inconclusive: !variant_result.vulnerable
                        && variant_result.details.to_ascii_lowercase().contains("inconclusive"),
                    details: variant_result.details,
                    cve: Some(variant_result.variant.cve().to_string()),
                    cwe: Some("CWE-310".to_string()),
                    severity,
                })
            })
            .collect())
    }

    pub async fn test_beast(&self) -> Result<VulnerabilityResult> {
        let protocol_result = self.protocol_tester.test_protocol(Protocol::TLS10).await?;

        if !protocol_result.supported {
            return Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::BEAST,
                vulnerable: false,
                inconclusive: false,
                details: "Server does not support TLS 1.0".to_string(),
                cve: Some("CVE-2011-3389".to_string()),
                cwe: Some("CWE-326".to_string()),
                severity: Severity::Info,
            });
        }

        let cipher_summary = self.cipher_tester.test_protocol_ciphers(Protocol::TLS10).await?;
        Ok(super::cipher_checks::evaluate_beast(Some(&cipher_summary)))
    }

    pub async fn test_renegotiation(&self) -> Result<VulnerabilityResult> {
        use crate::protocols::renegotiation::RenegotiationTester;

        let tester = RenegotiationTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Renegotiation,
            vulnerable: result.vulnerable,
            inconclusive: false,
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

        let mut tester = FallbackScsvTester::new(&self.target);
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
            inconclusive: result.details.to_ascii_lowercase().contains("inconclusive"),
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
            inconclusive: false,
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

        let tester = HeartbleedTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: result.vulnerable,
            inconclusive: false,
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

    pub async fn test_early_data(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::early_data::EarlyDataTester;

        let tester = EarlyDataTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::EarlyDataReplay,
            vulnerable: result.vulnerable,
            inconclusive: false,
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

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::PaddingOracle2016,
            vulnerable: result.vulnerable,
            inconclusive: false,
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
        use crate::vulnerabilities::opossum::{OpossumStatus, OpossumTester};

        let tester = OpossumTester::new(self.target.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Opossum,
            vulnerable: matches!(result.status, OpossumStatus::Vulnerable),
            inconclusive: matches!(result.status, OpossumStatus::Inconclusive),
            details: result.details,
            cve: Some("CVE-2022-0778".to_string()),
            cwe: Some("CWE-835".to_string()),
            severity: if matches!(result.status, OpossumStatus::Vulnerable) {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    pub async fn test_grease(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::grease::GreaseTester;

        let tester = GreaseTester::new(self.target.clone());
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
}
