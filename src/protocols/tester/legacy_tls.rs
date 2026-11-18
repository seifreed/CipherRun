use crate::constants::CONTENT_TYPE_ALERT;
use crate::protocols::handshake::ServerHelloParser;

use super::{Protocol, ProtocolProbeOutcome};

pub(super) fn classify_response(response: &[u8], protocol: Protocol) -> ProtocolProbeOutcome {
    if response.first() == Some(&CONTENT_TYPE_ALERT) {
        if response.len() < 7 {
            return ProtocolProbeOutcome::Inconclusive;
        }
        let alert_record_len = usize::from(u16::from_be_bytes([response[3], response[4]]));
        if alert_record_len != 2 || response.len() != 5 + alert_record_len {
            return ProtocolProbeOutcome::Inconclusive;
        }
        return ProtocolProbeOutcome::NotSupported;
    }

    match ServerHelloParser::parse(response) {
        Ok(server_hello) if server_hello.version == protocol => ProtocolProbeOutcome::Supported,
        Ok(_) => ProtocolProbeOutcome::NotSupported,
        Err(_) => ProtocolProbeOutcome::Inconclusive,
    }
}
