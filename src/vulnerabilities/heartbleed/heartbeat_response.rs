use crate::constants::CONTENT_TYPE_HEARTBEAT;

/// Validate that the response is a proper Heartbeat Response, not a TLS alert
/// or unrelated record.
pub(super) fn is_valid(response: &[u8]) -> bool {
    if response.len() < 8 {
        return false;
    }

    let content_type = response[0];
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

    let major = response[1];
    let minor = response[2];
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

    let record_len = u16::from_be_bytes([response[3], response[4]]) as usize;
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

    let heartbeat_type = response[5];
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

    let heartbeat_len = u16::from_be_bytes([response[6], response[7]]) as usize;
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

    #[test]
    fn rejects_malformed_heartbeat_record_fields() {
        let mut wrong_major = vec![
            0x18, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
        ];
        wrong_major[1] = 0x02;
        let mut wrong_minor = wrong_major.clone();
        wrong_minor[1] = 0x03;
        wrong_minor[2] = 0x04;

        let wrong_record_length = vec![
            0x18, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
        ];
        let wrong_heartbeat_type = vec![
            0x18, 0x03, 0x03, 0x00, 0x06, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
        ];
        let wrong_heartbeat_length = vec![
            0x18, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00, 0x02, 0xaa, 0xbb, 0xcc,
        ];

        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            for response in [
                &[][..],
                &[0x18, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00][..],
                &wrong_major,
                &wrong_minor,
                &wrong_record_length,
                &wrong_heartbeat_type,
                &wrong_heartbeat_length,
            ] {
                assert!(!is_valid(response), "unexpectedly accepted {response:?}");
            }
        });
    }
}
