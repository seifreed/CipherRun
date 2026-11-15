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
            event_name = "vulnerability.heartbleed.response_rejected",
            reason = "unexpected_content_type",
            content_type,
            expected_content_type = CONTENT_TYPE_HEARTBEAT,
            "Heartbleed response rejected"
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
            event_name = "vulnerability.heartbleed.response_rejected",
            reason = "unsupported_tls_version",
            tls_version_major = major,
            tls_version_minor = minor,
            "Heartbleed response rejected"
        );
        return false;
    }

    let Some(record_len) = read_u16_at(response, 3).map(usize::from) else {
        return false;
    };
    if record_len + 5 != response.len() {
        tracing::debug!(
            event_name = "vulnerability.heartbleed.response_rejected",
            reason = "record_length_mismatch",
            record_length = record_len,
            response_length = response.len(),
            "Heartbleed response rejected"
        );
        return false;
    }

    let Some(heartbeat_type) = response.get(5).copied() else {
        return false;
    };
    if heartbeat_type != 0x02 {
        tracing::debug!(
            event_name = "vulnerability.heartbleed.response_rejected",
            reason = "unexpected_heartbeat_type",
            heartbeat_type,
            expected_heartbeat_type = 0x02_u8,
            "Heartbleed response rejected"
        );
        return false;
    }

    let Some(heartbeat_len) = read_u16_at(response, 6).map(usize::from) else {
        return false;
    };
    if heartbeat_len + 3 != record_len {
        tracing::debug!(
            event_name = "vulnerability.heartbleed.response_rejected",
            reason = "heartbeat_length_mismatch",
            heartbeat_payload_length = heartbeat_len,
            record_length = record_len,
            "Heartbleed response rejected"
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
