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
