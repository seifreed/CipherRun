use crate::constants::CONTENT_TYPE_HEARTBEAT;
use crate::utils::byte_parse::read_u16_at;

/// Validate that the response is a proper Heartbeat Response, not a TLS alert
/// or unrelated record.
pub(super) fn is_valid(response: &[u8]) -> bool {
    if response.len() < 8 {
        return false;
    }

    let Some(content_type) = response.first().copied() else {
        return false;
    };
    if content_type != CONTENT_TYPE_HEARTBEAT {
        tracing::debug!(
            "Heartbleed: Response content type is not Heartbeat (0x{:02x}, expected 0x18)",
            content_type
        );
        return false;
    }

    let Some((&major, rest)) = response.get(1..).and_then(|tail| tail.split_first()) else {
        return false;
    };
    let Some(&minor) = rest.first() else {
        return false;
    };
    if major != 0x03 || !(0x01..=0x03).contains(&minor) {
        tracing::debug!(
            "Heartbleed: Response has unexpected TLS version 0x{:02x}{:02x}",
            major,
            minor
        );
        return false;
    }

    let Some(record_len) = read_u16_at(response, 3).map(usize::from) else {
        return false;
    };
    if record_len + 5 != response.len() {
        tracing::debug!(
            "Heartbleed: Response record length {} does not match buffer length {}",
            record_len,
            response.len()
        );
        return false;
    }

    let Some(heartbeat_type) = response.get(5).copied() else {
        return false;
    };
    if heartbeat_type != 0x02 {
        tracing::debug!(
            "Heartbleed: Response type is not HeartbeatResponse (0x{:02x}, expected 0x02)",
            heartbeat_type
        );
        return false;
    }

    let Some(heartbeat_len) = read_u16_at(response, 6).map(usize::from) else {
        return false;
    };
    if heartbeat_len + 3 != record_len {
        tracing::debug!(
            "Heartbleed: Heartbeat payload length {} does not match record length {}",
            heartbeat_len,
            record_len
        );
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_heartbeat_response() {
        assert!(is_valid(&[
            0x18, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
        ]));
    }

    #[test]
    fn rejects_tls_alerts() {
        assert!(!is_valid(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]));
    }
}
