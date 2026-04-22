use super::phases;
use crate::application::ScanRequest;
use crate::protocols::pre_handshake::PreHandshakeScanResult;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use std::sync::Arc;

pub(crate) fn build_scan_context(
    target: Target,
    request: ScanRequest,
    mtls_config: Option<MtlsConfig>,
    pre_handshake: Option<PreHandshakeScanResult>,
) -> phases::ScanContext {
    phases::ScanContext::new(target, Arc::new(request), mtls_config, pre_handshake)
}

pub(crate) fn build_phase_orchestrator(
    reporter: Arc<dyn phases::ScanProgressReporter>,
) -> phases::PhaseOrchestrator {
    phases::PhaseOrchestrator::with_reporter(reporter)
        .add_phase(Box::new(phases::ProtocolPhase::new()))
        .add_phase(Box::new(phases::CipherPhase::new()))
        .add_phase(Box::new(phases::CertificatePhase::new()))
        .add_phase(Box::new(phases::VulnerabilityPhase::new()))
        .add_phase(Box::new(phases::HttpHeadersPhase::new()))
        .add_phase(Box::new(phases::FingerprintPhase::new()))
        .add_phase(Box::new(phases::ClientSimPhase::new()))
        .add_phase(Box::new(phases::SignaturePhase::new()))
        .add_phase(Box::new(phases::GroupsPhase::new()))
        .add_phase(Box::new(phases::ClientCasPhase::new()))
        .add_phase(Box::new(phases::IntolerancePhase::new()))
        .add_phase(Box::new(phases::AlpnPhase::new()))
        .add_phase(Box::new(phases::PqcReadinessPhase::new()))
}
