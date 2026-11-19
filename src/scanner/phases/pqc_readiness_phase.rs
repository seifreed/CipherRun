// PQC Readiness Phase — assesses post-quantum cryptography readiness of the target

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use crate::pqc::PqcReadinessScorer;
use async_trait::async_trait;

pub struct PqcReadinessPhase;

impl PqcReadinessPhase {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PqcReadinessPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for PqcReadinessPhase {
    fn name(&self) -> &'static str {
        "Analyzing Post-Quantum Readiness"
    }

    fn should_run(&self, args: &ScanRequest) -> bool {
        args.scan.ciphers.pqc_readiness || args.scan.scope.full
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        let groups = context
            .results
            .advanced
            .as_ref()
            .and_then(|a| a.key_exchange_groups.as_ref());

        let cert_chain = context.results.certificate_chain.as_ref().map(|c| &c.chain);

        let assessment = PqcReadinessScorer::assess(groups, cert_chain, &context.results.protocols);
        context.results.advanced_mut().pqc_readiness = Some(assessment);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_readiness_phase_name() {
        assert_eq!(
            PqcReadinessPhase::new().name(),
            "Analyzing Post-Quantum Readiness"
        );
        assert_eq!(PqcReadinessPhase.name(), "Analyzing Post-Quantum Readiness");
    }

    #[tokio::test]
    async fn test_execute_stores_assessment_without_optional_inputs() {
        let mut context = super::super::test_scan_context(ScanRequest::default());

        PqcReadinessPhase::new()
            .execute(&mut context)
            .await
            .expect("assessment should succeed without optional inputs");

        assert!(context.results.advanced.unwrap().pqc_readiness.is_some());
    }

    #[tokio::test]
    async fn test_execute_accepts_available_groups_and_certificate_chain() {
        let mut context = super::super::test_scan_context(ScanRequest::default());
        context.results.advanced = Some(crate::scanner::AdvancedResults {
            key_exchange_groups: Some(crate::protocols::groups::GroupEnumerationResult {
                groups: Vec::new(),
                measured: false,
                details: String::new(),
            }),
            ..Default::default()
        });
        context.results.certificate_chain = Some(crate::scanner::CertificateAnalysisResult {
            chain: crate::certificates::parser::CertificateChain {
                certificates: Vec::new(),
                chain_length: 0,
                chain_size_bytes: 0,
            },
            validation: crate::certificates::validator::ValidationResult {
                valid: false,
                issues: Vec::new(),
                trust_chain_valid: false,
                hostname_match: false,
                not_expired: false,
                signature_valid: false,
                trusted_ca: None,
                platform_trust: None,
            },
            revocation: None,
        });

        PqcReadinessPhase::new()
            .execute(&mut context)
            .await
            .expect("assessment should accept available inputs");

        assert!(context.results.advanced.unwrap().pqc_readiness.is_some());
    }

    #[test]
    fn test_should_run_with_flag() {
        let phase = PqcReadinessPhase::new();
        let mut args = ScanRequest::default();
        args.scan.ciphers.pqc_readiness = true;
        assert!(phase.should_run(&args));
    }

    #[test]
    fn test_should_run_with_full() {
        let phase = PqcReadinessPhase::new();
        let mut args = ScanRequest::default();
        args.scan.scope.full = true;
        assert!(phase.should_run(&args));
    }

    #[test]
    fn test_should_not_run_by_default() {
        let phase = PqcReadinessPhase::new();
        let args = ScanRequest::default();
        assert!(!phase.should_run(&args));
    }
}
