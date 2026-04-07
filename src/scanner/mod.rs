// Scanner module - Main scanning engine

mod builders;
pub mod config;
pub mod default_port;
pub mod mass;
mod orchestration;
pub mod probe_status;
pub mod results;
mod service;

// Multi-IP modules - Scanner is now Send-compatible, enabling parallel IP scanning
pub mod aggregation;
pub mod inconsistency;
pub mod multi_ip;

// Phase-based scan orchestration (extracted from God Method)
pub mod phases;

// Re-export domain-specific configuration objects
pub use crate::protocols::ProtocolTestResult;
pub use config::{CertificateConfig, CipherTestConfig, ProtocolTestConfig};
pub use probe_status::{ErrorType as ProbeErrorType, ProbeStatus};
pub use results::{
    AdvancedResults, CertificateAnalysisResult, FingerprintResults, HttpResults, RatingResults,
    ScanMetadata, ScanResults, SniMethod,
};
pub use default_port::DefaultScannerPort;
pub use service::Scanner;

// Re-export progress reporter types for dependency injection
pub use phases::{ScanProgressReporter, SilentProgressReporter, TerminalProgressReporter};

#[cfg(test)]
mod tests;
