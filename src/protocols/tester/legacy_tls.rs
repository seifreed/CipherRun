use crate::constants::CONTENT_TYPE_ALERT;
use crate::protocols::handshake::ServerHelloParser;

use super::{Protocol, ProtocolProbeOutcome};

pub(super) fn classify_response(response: &[u8], protocol: Protocol) -> ProtocolProbeOutcome {
    if response.first() == Some(&CONTENT_TYPE_ALERT) {
        if response.len() < 7 {
            return ProtocolProbeOutcome::Inconclusive;
        }
        let Some(alert_record_len) = response
            .get(3..5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
        else {
            return ProtocolProbeOutcome::Inconclusive;
        };
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
