use super::{Protocol, VulnerabilityResult, VulnerabilityScanner, VulnerabilityType};
use crate::Result;
use crate::vulnerabilities::Severity;
use std::collections::HashMap;

pub(super) fn collect_result(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<VulnerabilityResult>,
    vuln_type: VulnerabilityType,
    test_name: &str,
) {
    match result {
        Ok(r) => results.push(r),
        Err(e) => {
            tracing::warn!("{} test failed: {}", test_name, e);
            // Add inconclusive result so user knows the test was attempted but failed
            results.push(VulnerabilityResult {
                vuln_type,
                vulnerable: false,
                inconclusive: true,
                details: format!(
                    "Test error: {} - unable to determine vulnerability status",
                    e
                ),
                cve: None,
                cwe: None,
                severity: Severity::Info,
            });
        }
    }
}

/// Collect multiple vulnerability results from a test that returns a vector.
/// On error, creates inconclusive results for each expected vulnerability type.
pub(super) fn collect_results(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<Vec<VulnerabilityResult>>,
    vuln_types: &[VulnerabilityType],
    test_name: &str,
) {
    match result {
        Ok(r) => results.extend(r),
        Err(e) => {
            tracing::warn!("{} test failed: {}", test_name, e);
            // Add inconclusive results for each expected vulnerability type
            // so users know these tests were attempted but failed
            for vuln_type in vuln_types {
                results.push(VulnerabilityResult {
                    vuln_type: *vuln_type,
                    vulnerable: false,
                    inconclusive: true,
                    details: format!(
                        "Test error: {} - unable to determine vulnerability status",
                        e
                    ),
                    cve: None,
                    cwe: None,
                    severity: Severity::Info,
                });
            }
        }
    }
}

pub(super) fn collect_optional_result(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<Option<VulnerabilityResult>>,
    vuln_type: VulnerabilityType,
    test_name: &str,
) {
    match result {
        Ok(Some(r)) => results.push(r),
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("{} test failed: {}", test_name, e);
            // Add inconclusive result so user knows the test was attempted but failed
            results.push(VulnerabilityResult {
                vuln_type,
                vulnerable: false,
                inconclusive: true,
                details: format!(
                    "Test error: {} - unable to determine vulnerability status",
                    e
                ),
                cve: None,
                cwe: None,
                severity: Severity::Info,
            });
        }
    }
}

impl VulnerabilityScanner {
    pub async fn test_requested(&self) -> Result<Vec<VulnerabilityResult>> {
        if self.broad_scan || !self.selected_checks.any() {
            return if self.fast_mode {
                self.test_fast().await
            } else {
                self.test_all().await
            };
        }

        self.run_selected_tests().await
    }

    pub async fn test_all(&self) -> Result<Vec<VulnerabilityResult>> {
        let protocols = self.detect_protocols().await?;
        let cipher_cache = self.cache_ciphers(&protocols).await?;
        Ok(self.run_vulnerability_tests(&cipher_cache).await)
    }

    pub async fn test_fast(&self) -> Result<Vec<VulnerabilityResult>> {
        let protocols = self.detect_protocols().await?;
        let cipher_cache = self.cache_ciphers(&protocols).await?;
        Ok(self.run_fast_vulnerability_tests(&cipher_cache).await)
    }

    pub(super) async fn detect_protocols(&self) -> Result<Vec<Protocol>> {
        let protocol_results = self.protocol_tester.test_all_protocols().await?;
        Ok(protocol_results
            .iter()
            .filter(|r| r.supported)
            .map(|r| r.protocol)
            .collect())
    }

    pub(super) async fn cache_ciphers(
        &self,
        protocols: &[Protocol],
    ) -> Result<HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>> {
        let mut cipher_cache = HashMap::new();

        for protocol in protocols {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let cipher_summary = self.cipher_tester.test_protocol_ciphers(*protocol).await?;
            cipher_cache.insert(*protocol, cipher_summary);
        }

        Ok(cipher_cache)
    }

    async fn run_vulnerability_tests(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Vec<VulnerabilityResult> {
        let mut results = Vec::new();

        let (
            drown_result,
            poodle_ssl_result,
            poodle_variants_result,
            rc4_result,
            null_result,
            beast_result,
            renegotiation_result,
            fallback_result,
            compression_result,
            heartbleed_result,
            early_data_result,
            padding_oracle_result,
            opossum_result,
            grease_result,
            ccs_result,
            ticketbleed_result,
            robot_result,
            breach_result,
            sweet32_result,
            freak_result,
            logjam_result,
            lucky13_result,
        ) = tokio::join!(
            self.test_drown(),
            self.test_poodle_ssl(),
            self.test_poodle_variants(),
            self.test_rc4_cached(cipher_cache),
            self.test_null_ciphers_cached(cipher_cache),
            self.test_beast_cached(cipher_cache),
            self.test_renegotiation_if_enabled(),
            self.test_fallback_if_enabled(),
            self.test_compression_if_enabled(),
            self.test_heartbleed_if_enabled(),
            self.test_early_data(),
            self.test_padding_oracle_2016(),
            self.test_opossum(),
            self.test_grease(),
            self.test_ccs(),
            self.test_ticketbleed(),
            self.test_robot(),
            self.test_breach(),
            self.test_sweet32(),
            self.test_freak(),
            self.test_logjam(),
            self.test_lucky13(),
        );

        collect_result(
            &mut results,
            drown_result,
            VulnerabilityType::DROWN,
            "DROWN",
        );
        collect_result(
            &mut results,
            poodle_ssl_result,
            VulnerabilityType::POODLE,
            "POODLE SSL",
        );
        collect_results(
            &mut results,
            poodle_variants_result,
            &[
                VulnerabilityType::ZombiePoodle,
                VulnerabilityType::GoldenDoodle,
                VulnerabilityType::SleepingPoodle,
                VulnerabilityType::OpenSsl0Length,
            ],
            "POODLE variants",
        );
        collect_result(&mut results, rc4_result, VulnerabilityType::RC4, "RC4");
        collect_result(
            &mut results,
            null_result,
            VulnerabilityType::NullCipher,
            "NULL ciphers",
        );
        collect_result(
            &mut results,
            beast_result,
            VulnerabilityType::BEAST,
            "BEAST",
        );
        collect_optional_result(
            &mut results,
            renegotiation_result,
            VulnerabilityType::Renegotiation,
            "Renegotiation",
        );
        collect_optional_result(
            &mut results,
            fallback_result,
            VulnerabilityType::TLSFallback,
            "TLS Fallback",
        );
        collect_optional_result(
            &mut results,
            compression_result,
            VulnerabilityType::CRIME,
            "Compression",
        );
        collect_optional_result(
            &mut results,
            heartbleed_result,
            VulnerabilityType::Heartbleed,
            "Heartbleed",
        );
        collect_result(
            &mut results,
            early_data_result,
            VulnerabilityType::EarlyDataReplay,
            "Early data",
        );
        collect_result(
            &mut results,
            padding_oracle_result,
            VulnerabilityType::PaddingOracle2016,
            "Padding oracle",
        );
        collect_result(
            &mut results,
            opossum_result,
            VulnerabilityType::Opossum,
            "Opossum",
        );
        collect_result(
            &mut results,
            grease_result,
            VulnerabilityType::GREASE,
            "GREASE",
        );
        collect_result(
            &mut results,
            ccs_result,
            VulnerabilityType::CCSInjection,
            "CCS",
        );
        collect_result(
            &mut results,
            ticketbleed_result,
            VulnerabilityType::Ticketbleed,
            "Ticketbleed",
        );
        collect_result(
            &mut results,
            robot_result,
            VulnerabilityType::ROBOT,
            "ROBOT",
        );
        collect_result(
            &mut results,
            breach_result,
            VulnerabilityType::BREACH,
            "BREACH",
        );
        collect_result(
            &mut results,
            sweet32_result,
            VulnerabilityType::SWEET32,
            "Sweet32",
        );
        collect_result(
            &mut results,
            freak_result,
            VulnerabilityType::FREAK,
            "FREAK",
        );
        collect_result(
            &mut results,
            logjam_result,
            VulnerabilityType::LOGJAM,
            "LOGJAM",
        );
        collect_result(
            &mut results,
            lucky13_result,
            VulnerabilityType::LUCKY13,
            "Lucky13",
        );

        results
    }

    async fn run_fast_vulnerability_tests(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Vec<VulnerabilityResult> {
        let mut results = Vec::new();

        let (
            drown_result,
            poodle_ssl_result,
            poodle_variants_result,
            rc4_result,
            null_result,
            beast_result,
            renegotiation_result,
            fallback_result,
            compression_result,
            heartbleed_result,
            early_data_result,
            ccs_result,
        ) = tokio::join!(
            self.test_drown(),
            self.test_poodle_ssl(),
            self.test_poodle_variants(),
            self.test_rc4_cached(cipher_cache),
            self.test_null_ciphers_cached(cipher_cache),
            self.test_beast_cached(cipher_cache),
            self.test_renegotiation_if_enabled(),
            self.test_fallback_if_enabled(),
            self.test_compression_if_enabled(),
            self.test_heartbleed_if_enabled(),
            self.test_early_data(),
            self.test_ccs(),
        );

        collect_result(
            &mut results,
            drown_result,
            VulnerabilityType::DROWN,
            "DROWN",
        );
        collect_result(
            &mut results,
            poodle_ssl_result,
            VulnerabilityType::POODLE,
            "POODLE SSL",
        );
        collect_results(
            &mut results,
            poodle_variants_result,
            &[
                VulnerabilityType::ZombiePoodle,
                VulnerabilityType::GoldenDoodle,
                VulnerabilityType::SleepingPoodle,
                VulnerabilityType::OpenSsl0Length,
            ],
            "POODLE variants",
        );
        collect_result(&mut results, rc4_result, VulnerabilityType::RC4, "RC4");
        collect_result(
            &mut results,
            null_result,
            VulnerabilityType::NullCipher,
            "NULL ciphers",
        );
        collect_result(
            &mut results,
            beast_result,
            VulnerabilityType::BEAST,
            "BEAST",
        );
        collect_optional_result(
            &mut results,
            renegotiation_result,
            VulnerabilityType::Renegotiation,
            "Renegotiation",
        );
        collect_optional_result(
            &mut results,
            fallback_result,
            VulnerabilityType::TLSFallback,
            "TLS Fallback",
        );
        collect_optional_result(
            &mut results,
            compression_result,
            VulnerabilityType::CRIME,
            "Compression",
        );
        collect_optional_result(
            &mut results,
            heartbleed_result,
            VulnerabilityType::Heartbleed,
            "Heartbleed",
        );
        collect_result(
            &mut results,
            early_data_result,
            VulnerabilityType::EarlyDataReplay,
            "Early data",
        );
        collect_result(
            &mut results,
            ccs_result,
            VulnerabilityType::CCSInjection,
            "CCS",
        );

        results
    }

    async fn run_selected_tests(&self) -> Result<Vec<VulnerabilityResult>> {
        let mut results = Vec::new();

        if self.selected_checks.is_enabled(&VulnerabilityType::DROWN) {
            collect_result(
                &mut results,
                self.test_drown().await,
                VulnerabilityType::DROWN,
                "DROWN",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::POODLE) {
            collect_result(
                &mut results,
                self.test_poodle_ssl().await,
                VulnerabilityType::POODLE,
                "POODLE SSL",
            );
            collect_results(
                &mut results,
                self.test_poodle_variants().await,
                &[
                    VulnerabilityType::ZombiePoodle,
                    VulnerabilityType::GoldenDoodle,
                    VulnerabilityType::SleepingPoodle,
                    VulnerabilityType::OpenSsl0Length,
                ],
                "POODLE variants",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::BEAST) {
            collect_result(
                &mut results,
                self.test_beast().await,
                VulnerabilityType::BEAST,
                "BEAST",
            );
        }
        if self
            .selected_checks
            .is_enabled(&VulnerabilityType::Renegotiation)
        {
            collect_optional_result(
                &mut results,
                self.test_renegotiation_if_enabled().await,
                VulnerabilityType::Renegotiation,
                "Renegotiation",
            );
        }
        if self
            .selected_checks
            .is_enabled(&VulnerabilityType::TLSFallback)
        {
            collect_optional_result(
                &mut results,
                self.test_fallback_if_enabled().await,
                VulnerabilityType::TLSFallback,
                "TLS Fallback",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::CRIME) {
            collect_optional_result(
                &mut results,
                self.test_compression_if_enabled().await,
                VulnerabilityType::CRIME,
                "Compression",
            );
        }
        if self
            .selected_checks
            .is_enabled(&VulnerabilityType::Heartbleed)
        {
            collect_optional_result(
                &mut results,
                self.test_heartbleed_if_enabled().await,
                VulnerabilityType::Heartbleed,
                "Heartbleed",
            );
        }
        if self
            .selected_checks
            .is_enabled(&VulnerabilityType::EarlyDataReplay)
        {
            collect_result(
                &mut results,
                self.test_early_data().await,
                VulnerabilityType::EarlyDataReplay,
                "Early data",
            );
        }
        if self
            .selected_checks
            .is_enabled(&VulnerabilityType::CCSInjection)
        {
            collect_result(
                &mut results,
                self.test_ccs().await,
                VulnerabilityType::CCSInjection,
                "CCS",
            );
        }
        if self
            .selected_checks
            .is_enabled(&VulnerabilityType::Ticketbleed)
        {
            collect_result(
                &mut results,
                self.test_ticketbleed().await,
                VulnerabilityType::Ticketbleed,
                "Ticketbleed",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::ROBOT) {
            collect_result(
                &mut results,
                self.test_robot().await,
                VulnerabilityType::ROBOT,
                "ROBOT",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::BREACH) {
            collect_result(
                &mut results,
                self.test_breach().await,
                VulnerabilityType::BREACH,
                "BREACH",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::SWEET32) {
            collect_result(
                &mut results,
                self.test_sweet32().await,
                VulnerabilityType::SWEET32,
                "Sweet32",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::FREAK) {
            collect_result(
                &mut results,
                self.test_freak().await,
                VulnerabilityType::FREAK,
                "FREAK",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::LOGJAM) {
            collect_result(
                &mut results,
                self.test_logjam().await,
                VulnerabilityType::LOGJAM,
                "LOGJAM",
            );
        }
        if self.selected_checks.is_enabled(&VulnerabilityType::LUCKY13) {
            collect_result(
                &mut results,
                self.test_lucky13().await,
                VulnerabilityType::LUCKY13,
                "Lucky13",
            );
        }

        Ok(results)
    }

    pub(super) async fn test_renegotiation_if_enabled(
        &self,
    ) -> Result<Option<VulnerabilityResult>> {
        if self.skip_renegotiation {
            return Ok(None);
        }
        self.test_renegotiation().await.map(Some)
    }

    pub(super) async fn test_fallback_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
        if self.skip_fallback {
            return Ok(None);
        }
        self.test_tls_fallback().await.map(Some)
    }

    pub(super) async fn test_compression_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
        if self.skip_compression {
            return Ok(None);
        }
        self.test_compression().await.map(Some)
    }

    pub(super) async fn test_heartbleed_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
        if self.skip_heartbleed {
            return Ok(None);
        }
        self.test_heartbleed().await.map(Some)
    }

    pub(super) async fn test_rc4_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_rc4(
            cipher_cache
                .iter()
                .map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub(super) async fn test_null_ciphers_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_null(
            cipher_cache
                .iter()
                .map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    #[cfg(test)]
    pub(super) async fn test_export_ciphers_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_export(
            cipher_cache
                .iter()
                .map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub(super) async fn test_beast_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_beast(
            cipher_cache.get(&Protocol::TLS10),
            cipher_cache.get(&Protocol::SSLv3),
        ))
    }
}
