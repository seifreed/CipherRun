use crate::Result;
pub(super) fn has_heartbeat_extension(data: &[u8]) -> Result<bool> {
    if data.len() < 44 {
        if data.first() == Some(&0x16) && data.get(5) == Some(&0x02) {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before session_id_len".to_string(),
            });
        }
        return Ok(false);
    }

    if data.first() != Some(&0x16) || data.get(5) != Some(&0x02) {
        return Ok(false);
    }

    // These field widths bound arithmetic; ranges are then checked against parent lengths.
    let record_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
    let record_end = 5 + record_len;
    if record_end > data.len() {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello record length extends beyond buffer".to_string(),
        });
    }
    let hs_len = (usize::from(data[6]) << 16) | (usize::from(data[7]) << 8) | usize::from(data[8]);
    let hs_end = 9 + hs_len;
    if hs_end > record_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello handshake length exceeds record length".to_string(),
        });
    }

    let sid_len = usize::from(data[43]);
    if sid_len > 32 {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello session_id_length exceeds TLS maximum".to_string(),
        });
    }
    let ext_offset = 47 + sid_len;
    if ext_offset == hs_end {
        return Ok(false);
    }

    let ext_start = ext_offset + 2;
    if ext_start > hs_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before extensions length".to_string(),
        });
    }

    let ext_total_len = usize::from(u16::from_be_bytes([data[ext_offset], data[ext_offset + 1]]));
    let ext_end = ext_start + ext_total_len;
    if ext_end > hs_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extension block extends beyond declared length".to_string(),
        });
    }
    if ext_end != hs_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extension block contains trailing bytes".to_string(),
        });
    }

    let mut pos = ext_start;
    while pos + 4 <= ext_end {
        let ext_header_end = pos + 4;
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len_offset = pos + 2;
        let ext_len = usize::from(u16::from_be_bytes([
            data[ext_len_offset],
            data[ext_len_offset + 1],
        ]));
        pos = ext_header_end;
        let next_pos = pos + ext_len;
        if next_pos > ext_end {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension data extends beyond declared length".to_string(),
            });
        }
        if ext_type == 0x000f {
            return Ok(true);
        }
        pos = next_pos;
    }
    if pos != ext_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extension block contains trailing bytes".to_string(),
        });
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello(extensions: Option<&[u8]>) -> Vec<u8> {
        let extension_len = extensions.map_or(0, <[u8]>::len);
        let body_len = 38 + extensions.map_or(0, |bytes| 2 + bytes.len());
        let record_len = 4 + body_len;
        let mut data = vec![0; 5 + record_len];
        data[0] = 0x16;
        data[1..3].copy_from_slice(&[0x03, 0x03]);
        data[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        data[5] = 0x02;
        data[6..9].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        data[9..11].copy_from_slice(&[0x03, 0x03]);
        data[43] = 0;
        if let Some(extensions) = extensions {
            data[47..49].copy_from_slice(&(extension_len as u16).to_be_bytes());
            data[49..].copy_from_slice(extensions);
        }
        data
    }

    fn set_u24(data: &mut [u8], offset: usize, value: usize) {
        data[offset..offset + 3].copy_from_slice(&(value as u32).to_be_bytes()[1..]);
    }

    #[test]
    fn detects_heartbeat_extension_and_accepts_no_extensions() {
        let no_extensions = server_hello(None);
        assert!(!has_heartbeat_extension(&no_extensions).unwrap());

        let heartbeat = server_hello(Some(&[0x00, 0x0f, 0x00, 0x00]));
        assert!(has_heartbeat_extension(&heartbeat).unwrap());

        let other_extension = server_hello(Some(&[0x00, 0x2b, 0x00, 0x00]));
        assert!(!has_heartbeat_extension(&other_extension).unwrap());
    }

    #[test]
    fn rejects_truncated_and_invalid_server_hello_headers() {
        assert!(!has_heartbeat_extension(&[0x16; 10]).unwrap());
        assert!(has_heartbeat_extension(&[0x16, 0x03, 0x03, 0, 0, 0x02]).is_err());

        let mut not_server_hello = server_hello(None);
        not_server_hello[5] = 0x01;
        assert!(!has_heartbeat_extension(&not_server_hello).unwrap());

        let mut overlong_record = server_hello(None);
        overlong_record[3..5].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(has_heartbeat_extension(&overlong_record).is_err());

        let mut overlong_handshake = server_hello(None);
        set_u24(&mut overlong_handshake, 6, 39);
        assert!(has_heartbeat_extension(&overlong_handshake).is_err());

        let mut oversized_session_id = server_hello(None);
        oversized_session_id[43] = 33;
        assert!(has_heartbeat_extension(&oversized_session_id).is_err());

        let mut missing_extensions_length = server_hello(None);
        set_u24(&mut missing_extensions_length, 6, 35);
        assert!(has_heartbeat_extension(&missing_extensions_length).is_err());
    }

    #[test]
    fn rejects_malformed_extension_block_lengths_and_entries() {
        let mut extension_past_handshake = server_hello(Some(&[0x00, 0x0f, 0x00, 0x00]));
        extension_past_handshake[47..49].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(has_heartbeat_extension(&extension_past_handshake).is_err());

        let mut trailing_handshake_bytes = server_hello(Some(&[0x00, 0x0f, 0x00, 0x00]));
        trailing_handshake_bytes.push(0);
        let record_len =
            u16::from_be_bytes([trailing_handshake_bytes[3], trailing_handshake_bytes[4]]);
        trailing_handshake_bytes[3..5].copy_from_slice(&(record_len + 1).to_be_bytes());
        set_u24(&mut trailing_handshake_bytes, 6, 45);
        assert!(has_heartbeat_extension(&trailing_handshake_bytes).is_err());

        let truncated_extension_header = server_hello(Some(&[0x00, 0x0f, 0x00]));
        assert!(has_heartbeat_extension(&truncated_extension_header).is_err());

        let truncated_extension_data = server_hello(Some(&[0x00, 0x0f, 0x00, 0x02, 0xaa]));
        assert!(has_heartbeat_extension(&truncated_extension_data).is_err());
    }
}
