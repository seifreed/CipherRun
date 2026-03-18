// Certificate Transparency Logs Streaming Module
//
// This module provides real-time streaming of Certificate Transparency logs
// for subdomain discovery and certificate intelligence gathering.

pub mod client;
pub mod deduplicator;
pub mod parser;
pub mod sources;
pub mod stats;
pub mod streamer;

pub use client::CtClient;
pub use deduplicator::Deduplicator;
pub use parser::{CertType, CtLogEntry, Parser};
pub use sources::{LogSource, SourceManager};
pub use stats::Stats;
pub use streamer::{CtConfig, CtStreamer};

use crate::error::TlsError;

/// Result type for CT logs operations
pub type Result<T> = std::result::Result<T, TlsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_logs_result_alias() {
        fn ok_result() -> Result<()> {
            Ok(())
        }

        assert!(ok_result().is_ok());
    }

    #[test]
    fn test_ct_logs_result_alias_err() {
        fn err_result() -> Result<()> {
            Err(crate::error::TlsError::Other("fail".to_string()))
        }

        assert!(err_result().is_err());
    }

    #[test]
    fn test_reexports_constructible() {
        let _client = CtClient::new();
        let _dedup = Deduplicator::default();
        let _config = CtConfig::default();
        let _stats = Stats::default();
    }
}
