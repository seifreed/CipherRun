use super::{Protocol, ProtocolTestResult};

pub(crate) fn supported_protocol_result(protocol: Protocol) -> ProtocolTestResult {
    ProtocolTestResult {
        protocol,
        supported: true,
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
