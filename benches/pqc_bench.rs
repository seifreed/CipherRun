use cipherrun::pqc::scanners::{CodeScanner, SshScanner};
use cipherrun::pqc::PqcReadinessScorer;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::io::Write;

fn bench_pqc_scorer_empty(c: &mut Criterion) {
    c.bench_function("pqc/scorer_empty_inputs", |b| {
        b.iter(|| PqcReadinessScorer::assess(black_box(None), black_box(None), black_box(&[])));
    });
}

fn bench_ssh_scanner(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("sshd_config");
    let mut f = std::fs::File::create(&config_path).expect("create");
    writeln!(
        f,
        "KexAlgorithms mlkem768nistp256-sha256@openssh.com,curve25519-sha256\n\
         HostKeyAlgorithms ecdsa-sha2-nistp256\n\
         PubkeyAcceptedAlgorithms rsa-sha2-256"
    )
    .expect("write");

    c.bench_function("pqc/ssh_scanner", |b| {
        b.iter(|| SshScanner::scan(black_box(&config_path)).expect("scan"));
    });
}

fn bench_code_scanner(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_path = dir.path().join("main.rs");
    let mut f = std::fs::File::create(&src_path).expect("create");
    writeln!(
        f,
        "use openssl::rsa::Rsa;\nuse openssl::ec::EcKey;\nfn main() {{}}"
    )
    .expect("write");

    c.bench_function("pqc/code_scanner", |b| {
        b.iter(|| CodeScanner::scan(black_box(dir.path())).expect("scan"));
    });
}

criterion_group!(benches, bench_pqc_scorer_empty, bench_ssh_scanner, bench_code_scanner);
criterion_main!(benches);
