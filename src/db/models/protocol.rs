// Protocol Record Model
// Represents detected TLS/SSL protocols for a scan

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Protocol record in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProtocolRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_id: Option<i64>,
    pub scan_id: i64,
    pub protocol_name: String,  // "TLS 1.2", "TLS 1.3", etc.
    pub enabled: bool,
    pub preferred: bool,
}

impl ProtocolRecord {
    /// Create new protocol record
    pub fn new(scan_id: i64, protocol_name: String, enabled: bool, preferred: bool) -> Self {
        Self {
            protocol_id: None,
            scan_id,
            protocol_name,
            enabled,
            preferred,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_record_creation() {
        let protocol = ProtocolRecord::new(1, "TLS 1.3".to_string(), true, true);
        assert_eq!(protocol.scan_id, 1);
        assert_eq!(protocol.protocol_name, "TLS 1.3");
        assert!(protocol.enabled);
        assert!(protocol.preferred);
    }
}
