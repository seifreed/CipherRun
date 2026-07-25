use super::CompressionProbeStatus;
use crate::constants::CONTENT_TYPE_HANDSHAKE;

fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

fn read_u24_at(data: &[u8], offset: usize) -> Option<usize> {
    let bytes = data.get(offset..offset.checked_add(3)?)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

fn slice_range(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    data.get(start..start.checked_add(len)?)
}

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
    tracing::debug!("Server compression method: {}", compression_method);
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
    if ext_start > data.len() {
        return CompressionProbeStatus::Inconclusive;
    }

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
    if ext_start > hs_end {
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

    #[test]
    fn tls_compression_rejects_short_server_hello() {
        assert_eq!(
            tls_compression_status(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x02]),
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
}
