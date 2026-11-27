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
        tracing::debug!(
            event_name = "vulnerability.drown.sslv2.response_classified",
            response_bytes = data.len(),
            outcome = "inconclusive",
            reason = "truncated_header",
            "DROWN SSLv2 response is too short to classify"
        );
        return Ok(Sslv2Status::Inconclusive);
    }

    let Some((header_len, record_len, record_total)) = record_shape(data) else {
        return Ok(Sslv2Status::NotSupported);
    };
    let is_reasonable_length = record_len > 0 && record_len <= 32767;
    let has_enough_data = data.len() > header_len && data.len() >= record_total;

    if !is_reasonable_length || !has_enough_data {
        tracing::debug!(
            event_name = "vulnerability.drown.sslv2.response_classified",
            response_bytes = data.len(),
            expected_bytes = record_total,
            record_bytes = record_len,
            outcome = "suspicious",
            reason = if is_reasonable_length {
                "truncated_record"
            } else {
                "invalid_record_length"
            },
            "DROWN SSLv2 response is malformed or truncated"
        );
        return Ok(Sslv2Status::Suspicious);
    }

    let Some(&msg_type) = data.get(header_len) else {
        return Ok(Sslv2Status::Suspicious);
    };

    match msg_type {
        0x04 => {
            tracing::debug!(
                event_name = "vulnerability.drown.sslv2.response_classified",
                message_type = msg_type,
                outcome = "confirmed",
                "DROWN SSLv2 ServerHello detected"
            );
            Ok(Sslv2Status::Confirmed)
        }
        0x00 => {
            tracing::warn!(
                event_name = "vulnerability.drown.sslv2.response_classified",
                message_type = msg_type,
                outcome = "probable",
                reason = "sslv2_error_message",
                "Server speaks SSLv2 but rejected the handshake"
            );
            Ok(Sslv2Status::Probable)
        }
        0x02 | 0x03 => {
            tracing::warn!(
                event_name = "vulnerability.drown.sslv2.response_classified",
                message_type = msg_type,
                outcome = "suspicious",
                reason = "client_message_from_server",
                "Server returned a client-only SSLv2 message"
            );
            Ok(Sslv2Status::Suspicious)
        }
        0x05..=0x07 => {
            tracing::debug!(
                event_name = "vulnerability.drown.sslv2.response_classified",
                message_type = msg_type,
                outcome = "probable",
                "Probable SSLv2 response detected"
            );
            Ok(Sslv2Status::Probable)
        }
        0x08 => {
            tracing::warn!(
                event_name = "vulnerability.drown.sslv2.response_classified",
                message_type = msg_type,
                outcome = "suspicious",
                reason = "client_message_from_server",
                "Server returned a client-only SSLv2 message"
            );
            Ok(Sslv2Status::Suspicious)
        }
        _ => {
            tracing::debug!(
                event_name = "vulnerability.drown.sslv2.response_classified",
                message_type = msg_type,
                outcome = "suspicious",
                reason = "unknown_message_type",
                "DROWN SSLv2-like response has an unknown message type"
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

    fn analyze_with_debug_logging(data: &[u8]) -> Result<Sslv2Status> {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::with_default(subscriber, || analyze_response(data))
    }

    #[test]
    fn recognizes_three_byte_record_shape() {
        assert_eq!(record_shape(&[0x00, 0x04, 0x00]), Some((3, 4, 7)));
    }

    #[test]
    fn rejects_tls_record_shape() {
        assert_eq!(record_shape(&[0x16, 0x03, 0x01]), None);
    }

    #[test]
    fn record_shape_covers_short_tls_and_two_byte_headers() {
        assert_eq!(record_shape(&[]), None);
        assert_eq!(record_shape(&[0x80]), None);
        for content_type in 0x14..=0x18 {
            assert_eq!(record_shape(&[content_type, 0x03]), None);
        }
        assert_eq!(record_shape(&[0x80, 0x04]), Some((2, 4, 6)));
        assert_eq!(record_shape(&[0x00, 0x03, 0x04]), Some((3, 3, 6)));
    }

    #[test]
    fn response_classification_covers_ssl2_message_types_and_lengths() {
        for (message_type, expected) in [
            (0x00, Sslv2Status::Probable),
            (0x02, Sslv2Status::Suspicious),
            (0x03, Sslv2Status::Suspicious),
            (0x04, Sslv2Status::Confirmed),
            (0x05, Sslv2Status::Probable),
            (0x06, Sslv2Status::Probable),
            (0x07, Sslv2Status::Probable),
            (0x08, Sslv2Status::Suspicious),
            (0xff, Sslv2Status::Suspicious),
        ] {
            assert_eq!(
                analyze_with_debug_logging(&[0x80, 0x01, message_type]).unwrap(),
                expected,
                "message type {message_type:#04x}"
            );
        }

        assert_eq!(
            analyze_with_debug_logging(&[]).unwrap(),
            Sslv2Status::Inconclusive
        );
        assert_eq!(
            analyze_with_debug_logging(&[0x80]).unwrap(),
            Sslv2Status::Inconclusive
        );
        assert_eq!(
            analyze_with_debug_logging(&[0x80, 0x00, 0x04]).unwrap(),
            Sslv2Status::Suspicious
        );
        assert_eq!(
            analyze_with_debug_logging(&[0x16, 0x03, 0x01]).unwrap(),
            Sslv2Status::NotSupported
        );
    }

    #[test]
    fn client_hello_encodes_the_ssl2_probe_fields() {
        let hello = client_hello();

        assert_eq!(hello.len(), 42);
        assert_eq!(hello[0] & 0x80, 0x80);
        assert_eq!(
            u16::from_be_bytes([hello[0] & 0x7f, hello[1]]) as usize,
            hello.len() - 2
        );
        assert_eq!(&hello[2..5], &[0x01, 0x00, 0x02]);
        assert_eq!(u16::from_be_bytes([hello[5], hello[6]]), 15);
        assert_eq!(u16::from_be_bytes([hello[7], hello[8]]), 0);
        assert_eq!(u16::from_be_bytes([hello[9], hello[10]]), 16);
        assert_eq!(
            &hello[11..26],
            &[
                0x07, 0x00, 0xc0, 0x01, 0x00, 0x80, 0x03, 0x00, 0x80, 0x06, 0x00, 0x40, 0x04, 0x00,
                0x80,
            ]
        );
        assert_eq!(
            &hello[26..],
            &(0_u8..16).map(|value| value * 13).collect::<Vec<_>>()
        );
    }

    #[test]
    fn export_client_hello_uses_export_ciphers_and_distinct_challenge() {
        let hello = export_client_hello();

        assert_eq!(hello.len(), 33);
        assert_eq!(hello[0] & 0x80, 0x80);
        assert_eq!(
            u16::from_be_bytes([hello[0] & 0x7f, hello[1]]) as usize,
            hello.len() - 2
        );
        assert_eq!(&hello[2..5], &[0x01, 0x00, 0x02]);
        assert_eq!(u16::from_be_bytes([hello[5], hello[6]]), 6);
        assert_eq!(u16::from_be_bytes([hello[7], hello[8]]), 0);
        assert_eq!(u16::from_be_bytes([hello[9], hello[10]]), 16);
        assert_eq!(&hello[11..17], &[0x02, 0x00, 0x80, 0x04, 0x00, 0x80]);
        assert_eq!(
            &hello[17..],
            &(0_u8..16).map(|value| value * 17).collect::<Vec<_>>()
        );
    }
}
