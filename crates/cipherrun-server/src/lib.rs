//! Stable API-server permission and job-backend contracts for CipherRun.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "PascalCase")]
pub enum Permission {
    /// Full access - can create, read, update, delete
    Admin,

    /// Standard user - can create and read scans
    User,

    /// Read-only access - can only read existing data
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum JobBackend {
    #[default]
    Memory,
    File,
    Database,
}
