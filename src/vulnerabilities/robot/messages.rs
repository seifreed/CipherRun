use crate::Result;
use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, HANDSHAKE_TYPE_FINISHED,
    VERSION_TLS_1_0,
};
use crate::utils::invalid_input_length::{u16_len, u24_len};

pub(super) fn invalid_client_key_exchange(variant: u8, key_len: usize) -> Result<Vec<u8>> {
    let record_body_len = key_len
        .checked_add(6)
        .ok_or_else(|| crate::TlsError::InvalidInput {
            message: "ROBOT ClientKeyExchange record length exceeds maximum".to_string(),
        })?;
    // The preceding +6 check also guarantees this smaller +2 cannot overflow.
    let handshake_body_len = key_len + 2;
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

#[cfg(test)]
mod tests {
    use super::{finished, invalid_client_key_exchange};

    #[test]
    fn invalid_client_key_exchange_builds_every_payload_variant() {
        let cases = [
            (0, vec![0x00; 4]),
            (1, vec![0xff; 4]),
            (2, vec![0, 1, 2, 3]),
            (3, vec![0xaa, 0x55, 0xaa, 0x55]),
            (4, vec![148, 71, 250, 173]),
        ];

        for (variant, expected_payload) in cases {
            let message = invalid_client_key_exchange(variant, expected_payload.len())
                .expect("small RSA ciphertext should fit the wire lengths");
            assert_eq!(&message[3..5], &[0, 10]);
            assert_eq!(&message[6..9], &[0, 0, 6]);
            assert_eq!(&message[9..11], &[0, 4]);
            assert_eq!(&message[11..], expected_payload);
        }
    }

    #[test]
    fn invalid_client_key_exchange_rejects_overflowing_and_unrepresentable_lengths() {
        assert!(invalid_client_key_exchange(0, usize::MAX).is_err());
        assert!(invalid_client_key_exchange(0, 65_530).is_err());
    }

    #[test]
    fn finished_message_has_the_expected_record_and_handshake_lengths() {
        let message = finished();
        assert_eq!(&message[3..5], &[0, 16]);
        assert_eq!(&message[6..9], &[0, 0, 12]);
        assert_eq!(message.len(), 21);
    }
}
