//! Dependency-light data contracts shared by CipherRun consumers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePackSource {
    pub organization: String,
    pub document: String,
    pub version: String,
    pub publication_date: String,
    pub url: String,
    pub last_reviewed_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulePackMetadata {
    pub version: String,
    pub source: RulePackSource,
    pub content_sha256: String,
}
