use cipherrun::application::{CompareScanIds, HostPortDaysInput, HostPortInput};
use cipherrun::utils::network::split_target_host_port;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_compare_scan_ids(c: &mut Criterion) {
    let mut group = c.benchmark_group("input_parsing/compare_scan_ids");

    for input in ["1:2", "1024:65535", "922337203685477580:42"] {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(input), input, |b, input| {
            b.iter(|| CompareScanIds::parse(black_box(input)).expect("benchmark input is valid"));
        });
    }

    group.finish();
}

fn bench_host_port_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("input_parsing/host_port");

    for input in ["example.com", "example.com:8443", "[2001:db8::1]:443"] {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(input), input, |b, input| {
            b.iter(|| {
                HostPortInput::parse_with_default_port(black_box(input), 443)
                    .expect("benchmark input is valid")
            });
        });
    }

    group.finish();
}

fn bench_host_port_days_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("input_parsing/host_port_days");

    for input in [
        "example.com:443:30",
        "scanner.example.com:8443:365",
        "[2001:db8::feed]:9443:7",
    ] {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(input), input, |b, input| {
            b.iter(|| {
                HostPortDaysInput::parse(black_box(input)).expect("benchmark input is valid")
            });
        });
    }

    group.finish();
}

fn bench_split_target_host_port(c: &mut Criterion) {
    let mut group = c.benchmark_group("input_parsing/split_target_host_port");

    for input in [
        "https://example.com:8443/path?q=1",
        "example.com:443",
        "[2001:db8::10]:9443",
    ] {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(input), input, |b, input| {
            b.iter(|| split_target_host_port(black_box(input)).expect("benchmark input is valid"));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_compare_scan_ids,
    bench_host_port_input,
    bench_host_port_days_input,
    bench_split_target_host_port
);
criterion_main!(benches);
