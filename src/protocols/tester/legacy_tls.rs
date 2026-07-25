use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, CONTENT_TYPE_ALERT, TLS_RECORD_HEADER_SIZE};
use crate::protocols::handshake::ServerHelloParser;

use super::{Protocol, ProtocolProbeOutcome};

pub(super) fn record_total_len(
    header: &[u8; TLS_RECORD_HEADER_SIZE],
) -> std::io::Result<Option<usize>> {
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = TLS_RECORD_HEADER_SIZE
        .checked_add(record_len)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLS record length overflow",
            )
        })?;
    if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
        return Ok(None);
    }
    Ok(Some(total_len))
}

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
