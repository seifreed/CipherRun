use cipherrun::application::ScanAssessment;
use cipherrun::compliance::{ComplianceEngine, FrameworkLoader};
use cipherrun::protocols::{Protocol, ProtocolTestResult};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const NIST_SP800_52R2: &str = include_str!("../data/compliance/nist_sp800_52r2.yaml");

fn sample_assessment() -> ScanAssessment {
    ScanAssessment {
        target: "benchmark.example:443".to_string(),
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

fn bench_framework_loading(c: &mut Criterion) {
    c.bench_function("compliance/load_nist_from_string", |b| {
        b.iter(|| {
            FrameworkLoader::load_from_string(black_box(NIST_SP800_52R2))
                .expect("embedded framework must load")
        });
    });
}

fn bench_compliance_evaluation(c: &mut Criterion) {
    let framework =
        FrameworkLoader::load_from_string(NIST_SP800_52R2).expect("embedded framework must load");
    let engine = ComplianceEngine::new(framework);
    let assessment = sample_assessment();

    c.bench_function("compliance/evaluate_nist_framework", |b| {
        b.iter(|| {
            let report = engine
                .evaluate(black_box(&assessment))
                .expect("benchmark assessment must evaluate");
            black_box(report.summary.failed + report.summary.warnings + report.summary.passed)
        });
    });
}

criterion_group!(
    benches,
    bench_framework_loading,
    bench_compliance_evaluation
);
criterion_main!(benches);
