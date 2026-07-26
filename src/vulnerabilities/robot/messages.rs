use crate::Result;
use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, HANDSHAKE_TYPE_FINISHED,
    VERSION_TLS_1_0,
};

fn length_error(context: &str) -> crate::TlsError {
    crate::TlsError::InvalidInput {
        message: format!("{context} exceeds maximum length"),
    }
}

fn u16_len(len: usize, context: &str) -> Result<u16> {
    u16::try_from(len).map_err(|_| length_error(context))
}

fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
    let len = u32::try_from(len).map_err(|_| length_error(context))?;
    if len > 0x00ff_ffff {
        return Err(length_error(context));
    }
    let bytes = len.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}

pub(super) fn invalid_client_key_exchange(variant: u8, key_len: usize) -> Result<Vec<u8>> {
    let record_body_len = key_len
        .checked_add(6)
        .ok_or_else(|| crate::TlsError::InvalidInput {
            message: "ROBOT ClientKeyExchange record length exceeds maximum".to_string(),
        })?;
    let handshake_body_len =
        key_len
            .checked_add(2)
            .ok_or_else(|| crate::TlsError::InvalidInput {
                message: "ROBOT ClientKeyExchange handshake length exceeds maximum".to_string(),
            })?;
    let record_body_len = u16_len(record_body_len, "ROBOT ClientKeyExchange record")?;
    let handshake_body_len = u24_len(handshake_body_len, "ROBOT ClientKeyExchange handshake")?;
    let key_len = u16_len(key_len, "ROBOT RSA ciphertext")?;
    let key_len_usize = usize::from(key_len);

    let mut msg = Vec::new();
    msg.push(CONTENT_TYPE_HANDSHAKE);
    msg.extend_from_slice(&VERSION_TLS_1_0.to_be_bytes());
    msg.extend_from_slice(&record_body_len.to_be_bytes());
    msg.push(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE);
    msg.extend_from_slice(&handshake_body_len);
    msg.extend_from_slice(&key_len.to_be_bytes());

    match variant {
        0 => msg.extend(std::iter::repeat_n(0x00u8, key_len_usize)),
        1 => msg.extend(std::iter::repeat_n(0xffu8, key_len_usize)),
        2 => {
            let mut byte = 0_u8;
            for _ in 0..key_len_usize {
                msg.push(byte);
                byte = byte.wrapping_add(1);
            }
        }
        3 => {
            for i in 0..key_len_usize {
                msg.push(if i % 2 == 0 { 0xAA } else { 0x55 });
            }
        }
        _ => {
            let mut byte = variant.wrapping_mul(37);
            for _ in 0..key_len_usize {
                msg.push(byte);
                byte = byte.wrapping_add(179);
            }
        }
    }

    Ok(msg)
}

pub(super) fn finished() -> Vec<u8> {
    vec![
        CONTENT_TYPE_HANDSHAKE,
        VERSION_TLS_1_0.to_be_bytes()[0],
        VERSION_TLS_1_0.to_be_bytes()[1],
        0x00,
        0x10,
        HANDSHAKE_TYPE_FINISHED,
        0x00,
        0x00,
        0x0c,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
}
