use super::Sslv2Status;
use crate::Result;

pub(super) fn record_shape(data: &[u8]) -> Option<(usize, usize, usize)> {
    let first = *data.first()?;
    let second = *data.get(1)?;
    if matches!(first, 0x14..=0x18) && second == 0x03 {
        return None;
    }
    if (first & 0x80) != 0 {
        let record_len = ((first & 0x7f) as usize) << 8 | second as usize;
        Some((2, record_len, 2 + record_len))
    } else {
        let record_len = ((first & 0x3f) as usize) << 8 | second as usize;
        Some((3, record_len, 3 + record_len))
    }
}

pub(super) fn analyze_response(data: &[u8]) -> Result<Sslv2Status> {
    if data.len() < 2 {
        return Ok(Sslv2Status::Inconclusive);
    }

    let Some((header_len, record_len, record_total)) = record_shape(data) else {
        return Ok(Sslv2Status::NotSupported);
    };
    let is_reasonable_length = record_len > 0 && record_len <= 32767;
    let has_enough_data = data.len() > header_len && data.len() >= record_total;

    if !is_reasonable_length || !has_enough_data {
        tracing::debug!(
            "DROWN: SSLv2 header detected but response truncated (len={}, expected={})",
            data.len(),
            record_total
        );
        return Ok(Sslv2Status::Suspicious);
    }

    let Some(&msg_type) = data.get(header_len) else {
        return Ok(Sslv2Status::Suspicious);
    };

    match msg_type {
        0x04 => {
            tracing::debug!("DROWN: SSLv2 ServerHello (0x04) confirmed");
            Ok(Sslv2Status::Confirmed)
        }
        0x00 => {
            tracing::warn!(
                "DROWN: SSLv2 Error (0x00) received - server speaks SSLv2 but rejected handshake, \
                 manual review recommended. Server may still be DROWN-vulnerable with different ciphers."
            );
            Ok(Sslv2Status::Probable)
        }
        0x02 | 0x03 => {
            tracing::warn!(
                "DROWN: Client-only SSLv2 message type 0x{:02x} received from server — protocol confusion, not SSLv2 support",
                msg_type
            );
            Ok(Sslv2Status::Suspicious)
        }
        0x05..=0x07 => {
            tracing::debug!(
                "DROWN: SSLv2 message type 0x{:02x} detected - SSLv2 probable",
                msg_type
            );
            Ok(Sslv2Status::Probable)
        }
        0x08 => {
            tracing::warn!(
                "DROWN: Client-only SSLv2 message 0x08 (ClientCertificate) received from server — protocol confusion"
            );
            Ok(Sslv2Status::Suspicious)
        }
        _ => {
            tracing::debug!(
                "DROWN: Suspicious SSLv2-like response with unknown message type 0x{:02x}",
                msg_type
            );
            Ok(Sslv2Status::Suspicious)
        }
    }
}

pub(super) fn client_hello() -> Vec<u8> {
    const CIPHERS: &[[u8; 3]] = &[
        [0x07, 0x00, 0xC0],
        [0x01, 0x00, 0x80],
        [0x03, 0x00, 0x80],
        [0x06, 0x00, 0x40],
        [0x04, 0x00, 0x80],
    ];
    build_client_hello(CIPHERS, 13)
}

pub(super) fn export_client_hello() -> Vec<u8> {
    const CIPHERS: &[[u8; 3]] = &[[0x02, 0x00, 0x80], [0x04, 0x00, 0x80]];
    build_client_hello(CIPHERS, 17)
}

fn build_client_hello(cipher_specs: &[[u8; 3]], challenge_multiplier: u8) -> Vec<u8> {
    let cipher_specs_len = u16::try_from(cipher_specs.len() * 3)
        .expect("static SSLv2 cipher specs length should fit u16");
    let session_id_len: u16 = 0;
    let challenge_len: u16 = 16;
    let body_len: u16 = 1 + 2 + 2 + 2 + 2 + cipher_specs_len + challenge_len;
    let body_len_bytes = body_len.to_be_bytes();
    let mut hello = vec![
        0x80 | (body_len_bytes[0] & 0x7f),
        body_len_bytes[1],
        0x01,
        0x00,
        0x02,
    ];
    hello.extend_from_slice(&cipher_specs_len.to_be_bytes());
    hello.extend_from_slice(&session_id_len.to_be_bytes());
    hello.extend_from_slice(&challenge_len.to_be_bytes());
    for cipher in cipher_specs {
        hello.extend_from_slice(cipher);
    }
    for i in 0_u8..16 {
        hello.push(i * challenge_multiplier);
    }
    hello
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_three_byte_record_shape() {
        assert_eq!(record_shape(&[0x00, 0x04, 0x00]), Some((3, 4, 7)));
    }

    #[test]
    fn rejects_tls_record_shape() {
        assert_eq!(record_shape(&[0x16, 0x03, 0x01]), None);
    }
}
