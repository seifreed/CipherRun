// Post-Quantum Cryptography (PQC) analysis module
//
// Provides PQC readiness assessment, migration roadmap generation,
// HNDL (Harvest-Now-Decrypt-Later) flow analysis, SSH/VPN/code scanning,
// and PQC algorithm benchmarking.

pub mod readiness;
#[cfg(feature = "pqc")]
pub mod roadmap;
#[cfg(feature = "pqc")]
pub mod scanners;

pub use readiness::{PqcLevel, PqcReadinessAssessment, PqcReadinessScorer};
