use super::{Protocol, Severity, VulnerabilityResult, VulnerabilityScanner, VulnerabilityType};
use crate::Result;

impl VulnerabilityScanner {
    pub async fn test_drown(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::drown::{DrownTester, Sslv2Status};

        let tester = DrownTester::new(self.target.clone())
            .with_starttls(self.starttls, self.starttls_hostname.clone());
        let result = tester.test().await?;
        // A server that speaks SSLv2 but rejected our probe (Probable) is not a
        // confirmed DROWN oracle, but it is not clean either — report it as
        // inconclusive (manual review with other ciphers/ports) rather than a
        // hard vulnerable verdict or a clean pass.
        let inconclusive = !result.vulnerable
            && matches!(
                result.sslv2_status,
                None | Some(Sslv2Status::Suspicious | Sslv2Status::Probable)
            );

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
        let (supported, inconclusive) =
            crate::vulnerabilities::cipher_probe::probe_supported_suites(
                &self.target,
                super::cipher_checks::RC4_CIPHER_SUITES,
                super::cipher_checks::WEAK_CIPHER_PROBE_PROTOCOLS,
                self.starttls,
            )
            .await;
        Ok(super::cipher_checks::rc4_probe_verdict(
            &supported,
            inconclusive,
        ))
    }

    pub async fn test_null_ciphers(&self) -> Result<VulnerabilityResult> {
        let (supported, inconclusive) =
            crate::vulnerabilities::cipher_probe::probe_supported_suites(
                &self.target,
                super::cipher_checks::NULL_CIPHER_SUITES,
                super::cipher_checks::WEAK_CIPHER_PROBE_PROTOCOLS,
                self.starttls,
            )
            .await;
        Ok(super::cipher_checks::null_probe_verdict(
            &supported,
            inconclusive,
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
            // An SSLv3 probe that could not be determined (e.g. a transport
            // anomaly on a host that still accepts TCP) must not be reported as
            // a definitive "does not support SSLv3".
            inconclusive: protocol_result.inconclusive,
            details: if protocol_result.supported {
                "Server supports SSLv3, vulnerable to POODLE attack".to_string()
            } else if protocol_result.inconclusive {
                "POODLE SSL test inconclusive - could not determine SSLv3 support".to_string()
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

            // Neither protocol probe reported support; distinguish a definitive
            // "not supported" from an undetermined probe (transport anomaly on a
            // host that still accepts TCP) so the latter is not a clean pass.
            let probes_inconclusive = tls10_result.inconclusive || ssl3_result.inconclusive;
            return Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::BEAST,
                vulnerable: false,
                inconclusive: probes_inconclusive,
                details: if probes_inconclusive {
                    "BEAST test inconclusive - could not determine TLS 1.0 / SSL 3.0 support"
                        .to_string()
                } else {
                    "Server does not support TLS 1.0 or SSL 3.0".to_string()
                },
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

        let tester = HeartbleedTester::new(&self.target)
            .with_sni(self.sni_hostname.clone())
            .with_starttls(self.starttls, self.starttls_hostname.clone());
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

        let tester = CcsInjectionTester::new(self.target.clone())
            .with_starttls(self.starttls, self.starttls_hostname.clone());
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

        let tester = TicketbleedTester::new(self.target.clone())
            .with_starttls(self.starttls, self.starttls_hostname.clone());
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

        let tester = RobotTester::new(self.target.clone())
            .with_starttls(self.starttls, self.starttls_hostname.clone());
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::ROBOT,
            vulnerable: result.vulnerable,
            inconclusive: matches!(
                result.status,
                RobotStatus::Inconclusive | RobotStatus::WeakOracle
            ),
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

        let tester = Sweet32Tester::new(self.target.clone()).with_starttls(self.starttls);
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

        let tester = FreakTester::new(self.target.clone()).with_starttls(self.starttls);
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

        let tester = LogjamTester::new(self.target.clone())
            .with_starttls(self.starttls, self.starttls_hostname.clone());
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

        let tester = Lucky13Tester::new(self.target.clone())
            .with_starttls(self.starttls, self.starttls_hostname.clone());
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
            // The tester already reports `inconclusive` when AES-CBC support
            // itself could not be determined (e.g. a transport stall on a host
            // that still accepts TCP). Honour it so such a probe is not
            // collapsed into a definitive "not vulnerable"; keep treating a
            // CBC-supported-but-unconfirmed result as inconclusive too.
            inconclusive: result.inconclusive || (result.cbc_supported && !result.vulnerable),
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

        // GREASE intolerance (RFC 8701) is a protocol-ossification /
        // interoperability robustness concern — an intolerant server may break
        // when future TLS values are deployed — not a security vulnerability.
        // Reporting it as `vulnerable` mislabels hardened servers (e.g. Google,
        // which tolerates most GREASE but rejected the combined probe) and
        // inflates the vulnerability count. Surface it informationally instead
        // (Info severity + details), never as a vulnerable verdict.
        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::GREASE,
            vulnerable: false,
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
#[path = "checks_tests.rs"]
mod tests;
