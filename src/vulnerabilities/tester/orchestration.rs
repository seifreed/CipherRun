use super::{Protocol, VulnerabilityResult, VulnerabilityScanner};
use crate::Result;
use std::collections::HashMap;

pub(super) fn collect_result(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<VulnerabilityResult>,
    test_name: &str,
) {
    match result {
        Ok(r) => results.push(r),
        Err(e) => tracing::warn!("{} test failed: {}", test_name, e),
    }
}

pub(super) fn collect_results(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<Vec<VulnerabilityResult>>,
    test_name: &str,
) {
    match result {
        Ok(r) => results.extend(r),
        Err(e) => tracing::warn!("{} test failed: {}", test_name, e),
    }
}

pub(super) fn collect_optional_result(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<Option<VulnerabilityResult>>,
    test_name: &str,
) {
    match result {
        Ok(Some(r)) => results.push(r),
        Ok(None) => {}
        Err(e) => tracing::warn!("{} test failed: {}", test_name, e),
    }
}

impl VulnerabilityScanner {
    pub async fn test_all(&self) -> Result<Vec<VulnerabilityResult>> {
        let protocols = self.detect_protocols().await?;
        let cipher_cache = self.cache_ciphers(&protocols).await?;
        Ok(self.run_vulnerability_tests(&cipher_cache).await)
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
            des3_result,
            null_result,
            export_result,
            beast_result,
            renegotiation_result,
            fallback_result,
            compression_result,
            heartbleed_result,
            early_data_result,
            padding_oracle_result,
            opossum_result,
            grease_result,
        ) = tokio::join!(
            self.test_drown(),
            self.test_poodle_ssl(),
            self.test_poodle_variants(),
            self.test_rc4_cached(cipher_cache),
            self.test_3des_cached(cipher_cache),
            self.test_null_ciphers_cached(cipher_cache),
            self.test_export_ciphers_cached(cipher_cache),
            self.test_beast_cached(cipher_cache),
            self.test_renegotiation_if_enabled(),
            self.test_fallback_if_enabled(),
            self.test_compression_if_enabled(),
            self.test_heartbleed_if_enabled(),
            self.test_early_data(),
            self.test_padding_oracle_2016(),
            self.test_opossum(),
            self.test_grease(),
        );

        collect_result(&mut results, drown_result, "DROWN");
        collect_result(&mut results, poodle_ssl_result, "POODLE SSL");
        collect_results(&mut results, poodle_variants_result, "POODLE variants");
        collect_result(&mut results, rc4_result, "RC4");
        collect_result(&mut results, des3_result, "3DES");
        collect_result(&mut results, null_result, "NULL ciphers");
        collect_result(&mut results, export_result, "EXPORT ciphers");
        collect_result(&mut results, beast_result, "BEAST");
        collect_optional_result(&mut results, renegotiation_result, "Renegotiation");
        collect_optional_result(&mut results, fallback_result, "TLS Fallback");
        collect_optional_result(&mut results, compression_result, "Compression");
        collect_optional_result(&mut results, heartbleed_result, "Heartbleed");
        collect_result(&mut results, early_data_result, "Early data");
        collect_result(&mut results, padding_oracle_result, "Padding oracle");
        collect_result(&mut results, opossum_result, "Opossum");
        collect_result(&mut results, grease_result, "GREASE");

        results
    }

    pub(super) async fn test_renegotiation_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
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
            cipher_cache.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub(super) async fn test_3des_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_3des(
            cipher_cache.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub(super) async fn test_null_ciphers_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_null(
            cipher_cache.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub(super) async fn test_export_ciphers_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_export(
            cipher_cache.iter().map(|(protocol, summary)| (*protocol, summary)),
        ))
    }

    pub(super) async fn test_beast_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        Ok(super::cipher_checks::evaluate_beast(cipher_cache.get(&Protocol::TLS10)))
    }
}
