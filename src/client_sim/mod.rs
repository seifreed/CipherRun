// Client simulation module

pub mod clients;
pub mod custom_handshake;
pub mod simulator;

#[cfg(test)]
mod tests {
    use super::simulator::ClientSimulationResult;
    use crate::protocols::Protocol;

    #[test]
    fn test_client_simulation_result_serialization() {
        let result = ClientSimulationResult {
            client_name: "Test Client".to_string(),
            client_id: "test".to_string(),
            success: true,
            protocol: Some(Protocol::TLS12),
            cipher: Some("TLS_RSA_WITH_AES_128_GCM_SHA256".to_string()),
            error: None,
            handshake_time_ms: Some(42),
            alpn: Some("h2".to_string()),
            key_exchange: Some("ECDHE".to_string()),
            forward_secrecy: true,
            certificate_type: Some("RSA 2048".to_string()),
        };

        let json = serde_json::to_string(&result).expect("test assertion should succeed");
        assert!(json.contains("Test Client"));
        assert!(json.contains("TLS12"));
    }
}
