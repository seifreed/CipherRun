use super::bytes;
use crate::Result;
use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, EXTENSION_RENEGOTIATION_INFO, HANDSHAKE_TYPE_CLIENT_HELLO,
    VERSION_TLS_1_2,
};

pub(super) fn with_renegotiation_info() -> Result<Vec<u8>> {
    build(true)
}

pub(super) fn without_renegotiation_info() -> Result<Vec<u8>> {
    build(false)
}

fn build(include_renegotiation_info: bool) -> Result<Vec<u8>> {
    let mut hello = Vec::new();

    hello.push(CONTENT_TYPE_HANDSHAKE);
    hello.extend_from_slice(&VERSION_TLS_1_2.to_be_bytes());

    let len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]);

    hello.push(HANDSHAKE_TYPE_CLIENT_HELLO);

    let hs_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    hello.extend_from_slice(&VERSION_TLS_1_2.to_be_bytes());

    let mut random_byte = 0_u8;
    for _ in 0..32 {
        hello.push(random_byte);
        random_byte = random_byte.wrapping_add(13);
    }

    hello.push(0x00); // empty session ID
    hello.extend_from_slice(&[0x00, 0x04, 0xc0, 0x2f, 0x00, 0x9c]);
    hello.extend_from_slice(&[0x01, 0x00]); // null compression

    if include_renegotiation_info {
        let ext_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        hello.extend_from_slice(&EXTENSION_RENEGOTIATION_INFO.to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x01, 0x00]);

        let ext_len = hello.len() - ext_pos - 2;
        bytes::write_u16_at(
            &mut hello,
            ext_pos,
            bytes::u16_len(ext_len, "ClientHello extensions length")?,
            "ClientHello extensions length placeholder",
        )?;
    }

    let hs_len = hello.len() - hs_len_pos - 3;
    bytes::write_u24_at(
        &mut hello,
        hs_len_pos,
        hs_len,
        "ClientHello handshake length placeholder",
    )?;

    let rec_len = hello.len() - len_pos - 2;
    bytes::write_u16_at(
        &mut hello,
        len_pos,
        bytes::u16_len(rec_len, "ClientHello record length")?,
        "ClientHello record length placeholder",
    )?;

    Ok(hello)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_length_matches_payload() {
        let hello = with_renegotiation_info().expect("ClientHello should build");
        let rec_len = bytes::read_u16_at(&hello, 3, "ClientHello record length").unwrap() as usize;

        assert_eq!(rec_len, hello.len() - 5);
    }

    #[test]
    fn renegotiation_info_extension_is_optional() {
        let with_ext = with_renegotiation_info().expect("ClientHello should build");
        let without_ext = without_renegotiation_info().expect("ClientHello should build");

        assert!(with_ext.windows(2).any(|w| w == [0xff, 0x01]));
        assert!(!without_ext.windows(2).any(|w| w == [0xff, 0x01]));
    }
}
