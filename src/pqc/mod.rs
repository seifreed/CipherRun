// Post-Quantum Cryptography (PQC) analysis module
//
// Provides PQC readiness assessment, migration roadmap generation,
// HNDL (Harvest-Now-Decrypt-Later) flow analysis, SSH/VPN/code scanning,
// and PQC algorithm benchmarking.

pub mod readiness;
pub mod roadmap;
pub mod scanners;

pub use readiness::{PqcLevel, PqcReadinessAssessment, PqcReadinessScorer};
