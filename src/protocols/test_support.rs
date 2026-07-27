use super::{Protocol, ProtocolTestResult};

pub(crate) fn protocol_result(protocol: Protocol, supported: bool) -> ProtocolTestResult {
    ProtocolTestResult {
        protocol,
        supported,
        inconclusive: false,
        preferred: false,
        ciphers_count: 0,
        heartbeat_enabled: None,
        handshake_time_ms: None,
        session_resumption_caching: None,
        session_resumption_tickets: None,
        secure_renegotiation: None,
    }
}

pub(crate) fn supported_protocol_result(protocol: Protocol) -> ProtocolTestResult {
    protocol_result(protocol, true)
}
