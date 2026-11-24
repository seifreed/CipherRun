use super::CompressionProbeStatus;
use crate::constants::CONTENT_TYPE_HANDSHAKE;
use crate::utils::byte_parse::{read_u16_at, read_u24_at, slice_range};

pub(super) fn tls_compression_status(response: &[u8]) -> CompressionProbeStatus {
    let Some(record_len) = read_u16_at(response, 3).map(usize::from) else {
        return CompressionProbeStatus::Inconclusive;
    };
    if record_len + 5 > response.len() {
        return CompressionProbeStatus::Inconclusive;
    }
    if response.first() != Some(&CONTENT_TYPE_HANDSHAKE) || response.get(5) != Some(&0x02) {
        return CompressionProbeStatus::Disabled;
    }
    if response.len() <= 43 {
        return CompressionProbeStatus::Inconclusive;
    }
    let Some(session_id_len) = response.get(43).copied().map(usize::from) else {
        return CompressionProbeStatus::Inconclusive;
    };
    if session_id_len > 32 {
        return CompressionProbeStatus::Inconclusive;
    }
    let Some(compression_offset) = 44usize
        .checked_add(session_id_len)
        .and_then(|cipher_offset| cipher_offset.checked_add(2))
    else {
        return CompressionProbeStatus::Inconclusive;
    };
    let Some(record_end) = 5usize.checked_add(record_len) else {
        return CompressionProbeStatus::Inconclusive;
    };
    if compression_offset >= record_end || response.len() <= compression_offset {
        return CompressionProbeStatus::Inconclusive;
    }
    let Some(compression_method) = response.get(compression_offset).copied() else {
        return CompressionProbeStatus::Inconclusive;
    };
    tracing::debug!(
        event_name = "vulnerability.crime.server_hello.compression_classified",
        compression_method,
        outcome = if compression_method == 0x01 {
            "enabled"
        } else {
            "disabled"
        },
        "CRIME compression method classified"
    );
    if compression_method == 0x01 {
        CompressionProbeStatus::Enabled
    } else {
        CompressionProbeStatus::Disabled
    }
}

pub(super) fn spdy_compression_status(data: &[u8]) -> CompressionProbeStatus {
    if data.len() < 6 || data.first() != Some(&0x16) || data.get(5) != Some(&0x02) {
        return CompressionProbeStatus::Disabled;
    }

    let sid_offset = 43;
    if sid_offset >= data.len() {
        return CompressionProbeStatus::Inconclusive;
    }
    let Some(sid_len) = data.get(sid_offset).copied().map(usize::from) else {
        return CompressionProbeStatus::Inconclusive;
    };
    let Some(ext_len_offset) = sid_offset
        .checked_add(1)
        .and_then(|offset| offset.checked_add(sid_len))
        .and_then(|offset| offset.checked_add(2 + 1))
    else {
        return CompressionProbeStatus::Inconclusive;
    };
    let Some(ext_start) = ext_len_offset.checked_add(2) else {
        return CompressionProbeStatus::Inconclusive;
    };

    let Some(record_len) = read_u16_at(data, 3).map(usize::from) else {
        return CompressionProbeStatus::Inconclusive;
    };
    let Some(record_end) = 5usize.checked_add(record_len) else {
        return CompressionProbeStatus::Inconclusive;
    };
    if record_end > data.len() {
        return CompressionProbeStatus::Inconclusive;
    }
    let Some(hs_len) = read_u24_at(data, 6) else {
        return CompressionProbeStatus::Inconclusive;
    };
    let Some(hs_end) = 9usize.checked_add(hs_len) else {
        return CompressionProbeStatus::Inconclusive;
    };
    if hs_end > record_end {
        return CompressionProbeStatus::Inconclusive;
    }
    if ext_len_offset == hs_end {
        return CompressionProbeStatus::Disabled;
    }
    if ext_start > data.len() || ext_start > hs_end {
        return CompressionProbeStatus::Inconclusive;
    }

    let Some(ext_total) = read_u16_at(data, ext_len_offset).map(usize::from) else {
        return CompressionProbeStatus::Inconclusive;
    };
    let Some(ext_end) = ext_start.checked_add(ext_total) else {
        return CompressionProbeStatus::Inconclusive;
    };
    if ext_end > hs_end || ext_end != hs_end {
        return CompressionProbeStatus::Inconclusive;
    }

    let mut pos = ext_start;
    let mut spdy_detected = false;
    while let Some(ext_header_end) = pos.checked_add(4).filter(|&end| end <= ext_end) {
        let Some(ext_type) = read_u16_at(data, pos) else {
            return CompressionProbeStatus::Inconclusive;
        };
        let Some(ext_len_offset) = pos.checked_add(2) else {
            return CompressionProbeStatus::Inconclusive;
        };
        let Some(ext_len) = read_u16_at(data, ext_len_offset).map(usize::from) else {
            return CompressionProbeStatus::Inconclusive;
        };
        pos = ext_header_end;
        let Some(next_pos) = pos.checked_add(ext_len) else {
            return CompressionProbeStatus::Inconclusive;
        };
        if next_pos > ext_end {
            return CompressionProbeStatus::Inconclusive;
        }

        if ext_type == 0x3374 && npn_has_spdy(data, pos, next_pos) {
            spdy_detected = true;
        }

        pos = next_pos;
    }
    if pos != ext_end {
        return CompressionProbeStatus::Inconclusive;
    }

    if spdy_detected {
        CompressionProbeStatus::Enabled
    } else {
        CompressionProbeStatus::Disabled
    }
}

fn npn_has_spdy(data: &[u8], mut proto_pos: usize, proto_end: usize) -> bool {
    while proto_pos < proto_end {
        let Some(proto_len) = data.get(proto_pos).copied().map(usize::from) else {
            return false;
        };
        let Some(proto_start) = proto_pos.checked_add(1) else {
            return false;
        };
        proto_pos = proto_start;
        let Some(next_proto_pos) = proto_pos.checked_add(proto_len) else {
            return false;
        };
        if next_proto_pos > proto_end {
            return false;
        }
        if let Some(proto_bytes) = slice_range(data, proto_pos, proto_len)
            && let Ok(proto) = std::str::from_utf8(proto_bytes)
            && proto.starts_with("spdy/")
        {
            return true;
        }
        proto_pos = next_proto_pos;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello(session_id: &[u8], extensions: Option<&[u8]>) -> Vec<u8> {
        let extension_block = extensions.map_or_else(Vec::new, |extensions| {
            let mut block = Vec::with_capacity(2 + extensions.len());
            block.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            block.extend_from_slice(extensions);
            block
        });
        let body_len = 38 + extension_block.len();
        let handshake_len = body_len as u32;
        let record_len = 4 + body_len;
        let mut response = vec![0x16, 0x03, 0x03];
        response.extend_from_slice(&(record_len as u16).to_be_bytes());
        response.push(0x02);
        response.extend_from_slice(&handshake_len.to_be_bytes()[1..]);
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&[0; 32]);
        response.push(session_id.len() as u8);
        response.extend_from_slice(session_id);
        response.extend_from_slice(&[0x13, 0x01, 0x00]);
        response.extend_from_slice(&extension_block);
        response
    }

    fn npn_extension(protocols: &[&[u8]]) -> Vec<u8> {
        let mut payload = Vec::new();
        for protocol in protocols {
            payload.push(protocol.len() as u8);
            payload.extend_from_slice(protocol);
        }
        let mut extension = vec![0x33, 0x74];
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend_from_slice(&payload);
        extension
    }

    #[test]
    fn tls_compression_rejects_short_server_hello() {
        assert_eq!(
            tls_compression_status(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x02]),
            CompressionProbeStatus::Inconclusive
        );
    }

    #[test]
    fn tls_compression_classifies_methods_and_rejects_malformed_records() {
        let mut enabled = server_hello(&[], None);
        enabled[46] = 1;
        assert_eq!(
            tls_compression_status(&enabled),
            CompressionProbeStatus::Enabled
        );
        assert_eq!(
            tls_compression_status(&server_hello(&[], None)),
            CompressionProbeStatus::Disabled
        );

        let mut wrong_content_type = server_hello(&[], None);
        wrong_content_type[0] = 0x15;
        assert_eq!(
            tls_compression_status(&wrong_content_type),
            CompressionProbeStatus::Disabled
        );

        let mut wrong_handshake_type = server_hello(&[], None);
        wrong_handshake_type[5] = 0x01;
        assert_eq!(
            tls_compression_status(&wrong_handshake_type),
            CompressionProbeStatus::Disabled
        );

        let mut oversized_session_id = server_hello(&[0; 33], None);
        assert_eq!(
            tls_compression_status(&oversized_session_id),
            CompressionProbeStatus::Inconclusive
        );

        oversized_session_id[3..5].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            tls_compression_status(&oversized_session_id),
            CompressionProbeStatus::Inconclusive
        );
    }

    #[test]
    fn spdy_status_treats_non_server_hello_as_disabled() {
        assert_eq!(
            spdy_compression_status(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]),
            CompressionProbeStatus::Disabled
        );
    }

    #[test]
    fn spdy_status_classifies_npn_protocols_and_validates_extension_bounds() {
        assert_eq!(
            spdy_compression_status(&server_hello(&[], None)),
            CompressionProbeStatus::Disabled
        );

        let spdy = npn_extension(&[b"http/1.1", b"spdy/3"]);
        assert_eq!(
            spdy_compression_status(&server_hello(&[], Some(&spdy))),
            CompressionProbeStatus::Enabled
        );

        let http = npn_extension(&[b"http/1.1"]);
        assert_eq!(
            spdy_compression_status(&server_hello(&[], Some(&http))),
            CompressionProbeStatus::Disabled
        );

        let mut malformed_extension = spdy;
        malformed_extension[3] = u8::MAX;
        assert_eq!(
            spdy_compression_status(&server_hello(&[], Some(&malformed_extension))),
            CompressionProbeStatus::Inconclusive
        );

        let mut truncated_record = server_hello(&[], Some(&http));
        truncated_record[4] = 1;
        assert_eq!(
            spdy_compression_status(&truncated_record),
            CompressionProbeStatus::Inconclusive
        );
    }
}
