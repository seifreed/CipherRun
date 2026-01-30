// Kani Formal Verification Proof Harnesses
//
// This module contains proof harnesses for verifying security-critical code paths
// in the CipherRun TLS/SSL scanner using Kani formal verification.
//
// To run verification:
//   cargo kani --tests
//
// To run a specific proof:
//   cargo kani --harness <harness_name>
//
// Proofs verify:
// - Absence of panics
// - Absence of buffer overflows
// - Absence of integer overflows
// - Memory safety

#[cfg(kani)]
pub mod tls_parsing;

#[cfg(kani)]
pub mod vulnerability_testers;

#[cfg(kani)]
pub mod certificate_parsing;

#[cfg(kani)]
pub mod protocol_conversion;
