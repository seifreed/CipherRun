#![no_main]

use cipherrun::application::ScanAssessment;
use cipherrun::compliance::{ComplianceEngine, FrameworkLoader};
use cipherrun::protocols::{Protocol, ProtocolTestResult};
use libfuzzer_sys::fuzz_target;

fn sample_assessment() -> ScanAssessment {
    ScanAssessment {
        target: "fuzz.example:443".to_string(),
        any_supported_protocols: vec![Protocol::TLS12, Protocol::TLS13],
        protocols: vec![
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 18,
                heartbeat_enabled: Some(false),
                handshake_time_ms: Some(42),
                session_resumption_caching: Some(true),
                session_resumption_tickets: Some(true),
                secure_renegotiation: Some(true),
            },
            ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                inconclusive: false,
                preferred: true,
                ciphers_count: 5,
                heartbeat_enabled: Some(false),
                handshake_time_ms: Some(31),
                session_resumption_caching: Some(true),
                session_resumption_tickets: Some(true),
                secure_renegotiation: Some(true),
            },
        ],
        ..Default::default()
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(framework) = FrameworkLoader::load_from_string(input) {
        let engine = ComplianceEngine::new(framework);
        let assessment = sample_assessment();
        let _ = engine.evaluate(&assessment);
    }
});
