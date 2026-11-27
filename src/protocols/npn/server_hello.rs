use crate::Result;
use crate::utils::result_byte_parse as parse_bytes;

const MAX_PROTOCOLS: usize = 100;

pub(super) fn is_parseable(response: &[u8]) -> bool {
    if response.len() < 47 || response.first() != Some(&0x16) || response.get(5) != Some(&0x02) {
        return false;
    }

    let Some(record_len) = parse_bytes::read_u16_at(response, 3, "NPN ServerHello record length")
        .ok()
        .map(usize::from)
    else {
        return false;
    };
    if 5 + record_len > response.len() {
        return false;
    }

    let Some(handshake_len) =
        parse_bytes::read_u24_at(response, 6, "NPN ServerHello handshake length").ok()
    else {
        return false;
    };
    let Some(handshake_end) = 9usize.checked_add(handshake_len) else {
        return false;
    };
    if handshake_end > 5 + record_len {
        return false;
    }

    let Some(sid_len) = parse_bytes::read_u8_at(response, 43, "NPN ServerHello session ID length")
        .ok()
        .map(usize::from)
    else {
        return false;
    };
    let min_after_sid = 44 + sid_len + 2 + 1;
    min_after_sid <= handshake_end
}

pub(super) fn parse_npn_protocols(response: &[u8]) -> Result<Vec<String>> {
    let mut protocols = Vec::new();
    if response.len() < 44 || response.first() != Some(&0x16) || response.get(5) != Some(&0x02) {
        return Ok(protocols);
    }

    let record_len =
        parse_bytes::read_u16_at(response, 3, "NPN ServerHello record length")? as usize;
    let record_end = 5usize
        .checked_add(record_len)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "NPN ServerHello record length overflow".to_string(),
        })?;
    if record_end > response.len() {
        return Err(crate::TlsError::ParseError {
            message: "NPN ServerHello record length exceeds available data".to_string(),
        });
    }

    let handshake_len = parse_bytes::read_u24_at(response, 6, "NPN ServerHello handshake length")?;
    let handshake_end =
        9usize
            .checked_add(handshake_len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "NPN ServerHello handshake length overflow".to_string(),
            })?;
    if handshake_end > record_end {
        return Err(crate::TlsError::ParseError {
            message: "NPN ServerHello handshake length exceeds record length".to_string(),
        });
    }

    let sid_len =
        parse_bytes::read_u8_at(response, 43, "NPN ServerHello session ID length")? as usize;
    let Some(ext_len_offset) = 44usize
        .checked_add(sid_len)
        .and_then(|offset| offset.checked_add(2 + 1))
    else {
        return Ok(protocols);
    };
    let Some(ext_start) = ext_len_offset.checked_add(2) else {
        return Ok(protocols);
    };
    if ext_len_offset == handshake_end {
        return Ok(protocols);
    }
    if ext_len_offset > handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "NPN ServerHello fields exceed handshake length".to_string(),
        });
    }
    if ext_start > handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "NPN extensions length truncated".to_string(),
        });
    }

    let ext_total =
        parse_bytes::read_u16_at(response, ext_len_offset, "NPN extensions length")? as usize;
    let ext_end = ext_start
        .checked_add(ext_total)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "NPN extension block length overflow".to_string(),
        })?;
    if ext_end > handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "NPN extension block extends beyond handshake length".to_string(),
        });
    }
    if ext_end != handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "NPN extension block contains trailing bytes".to_string(),
        });
    }

    let mut pos = ext_start;
    while let Some(ext_header_end) = pos.checked_add(4).filter(|&end| end <= ext_end) {
        let ext_type = parse_bytes::read_u16_at(response, pos, "NPN extension type")?;
        let ext_len_offset = pos
            .checked_add(2)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "NPN extension length offset overflow".to_string(),
            })?;
        let ext_len =
            parse_bytes::read_u16_at(response, ext_len_offset, "NPN extension length")? as usize;
        pos = ext_header_end;
        let ext_data_end = pos
            .checked_add(ext_len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "NPN extension data length overflow".to_string(),
            })?;
        if ext_data_end > ext_end {
            return Err(crate::TlsError::ParseError {
                message: "NPN extension data extends beyond declared length".to_string(),
            });
        }

        if ext_type == 0x3374 {
            parse_protocol_list(response, pos, ext_data_end, &mut protocols)?;
        }

        pos = ext_data_end;
    }
    if pos != ext_end {
        return Err(crate::TlsError::ParseError {
            message: "NPN extension block contains truncated header".to_string(),
        });
    }

    Ok(protocols)
}

fn parse_protocol_list(
    response: &[u8],
    mut npn_pos: usize,
    npn_end: usize,
    protocols: &mut Vec<String>,
) -> Result<()> {
    while npn_pos < npn_end && npn_pos < response.len() && protocols.len() < MAX_PROTOCOLS {
        let proto_len =
            parse_bytes::read_u8_at(response, npn_pos, "NPN protocol name length")? as usize;
        npn_pos += 1;
        if proto_len == 0 {
            return Err(crate::TlsError::ParseError {
                message: "NPN protocol name length cannot be zero".to_string(),
            });
        }
        let proto_end =
            npn_pos
                .checked_add(proto_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "NPN protocol name length overflow".to_string(),
                })?;
        if proto_end > npn_end {
            return Err(crate::TlsError::ParseError {
                message: "NPN protocol name extends beyond extension data".to_string(),
            });
        }
        let proto = String::from_utf8(
            parse_bytes::slice_range(response, npn_pos, proto_len, "NPN protocol name")?.to_vec(),
        )
        .map_err(|error| crate::TlsError::ParseError {
            message: format!("Invalid NPN protocol name UTF-8: {error}"),
        })?;
        protocols.push(proto);
        npn_pos = proto_end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let handshake_len = body.len();
        let record_len = handshake_len + 4;
        let mut response = vec![0x16, 0x03, 0x03];
        response.extend_from_slice(&(record_len as u16).to_be_bytes());
        response.push(0x02);
        response.extend_from_slice(&[
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ]);
        response.extend_from_slice(&body);
        response
    }

    fn npn_extension(protocols: &[u8]) -> Vec<u8> {
        let mut extension = vec![0x33, 0x74];
        extension.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
        extension.extend_from_slice(protocols);
        extension
    }

    #[test]
    fn rejects_zero_length_protocol_names() {
        let mut protocols = Vec::new();
        let err = parse_protocol_list(&[0x00], 0, 1, &mut protocols)
            .expect_err("zero-length protocol should fail");
        assert!(err.to_string().contains("cannot be zero"));
    }

    #[test]
    fn parses_protocol_list() {
        let data = [
            0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let mut protocols = Vec::new();
        parse_protocol_list(&data, 0, data.len(), &mut protocols)
            .expect("protocol list should parse");
        assert_eq!(protocols, ["h2", "http/1.1"]);
    }

    #[test]
    fn parses_npn_serverhello_protocols_and_empty_extension_blocks() {
        let protocols = [
            0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let response = server_hello(&npn_extension(&protocols));

        assert!(is_parseable(&response));
        assert_eq!(parse_npn_protocols(&response).unwrap(), ["h2", "http/1.1"]);

        let response = server_hello(&[]);
        assert!(is_parseable(&response));
        assert!(parse_npn_protocols(&response).unwrap().is_empty());
    }

    #[test]
    fn rejects_npn_serverhello_record_and_handshake_bounds() {
        let valid = server_hello(&[]);
        assert!(!is_parseable(&[]));
        assert!(!is_parseable(&[0; 47]));
        assert!(parse_npn_protocols(&valid[..43]).unwrap().is_empty());

        let mut wrong_record_type = valid.clone();
        wrong_record_type[0] = 0x15;
        assert!(!is_parseable(&wrong_record_type));
        assert!(parse_npn_protocols(&wrong_record_type).unwrap().is_empty());

        let mut wrong_handshake_type = valid.clone();
        wrong_handshake_type[5] = 0x01;
        assert!(!is_parseable(&wrong_handshake_type));
        assert!(
            parse_npn_protocols(&wrong_handshake_type)
                .unwrap()
                .is_empty()
        );

        let mut truncated_record = valid.clone();
        truncated_record[4] = truncated_record[4].saturating_sub(1);
        assert!(!is_parseable(&truncated_record));
        assert!(parse_npn_protocols(&truncated_record).is_err());

        let mut handshake_past_record = valid;
        handshake_past_record[8] = handshake_past_record[8].saturating_add(1);
        assert!(!is_parseable(&handshake_past_record));
        assert!(parse_npn_protocols(&handshake_past_record).is_err());
    }

    #[test]
    fn rejects_malformed_npn_extension_and_protocol_lengths() {
        let mut too_short_handshake = server_hello(&[]);
        too_short_handshake[8] = 37;
        assert!(parse_npn_protocols(&too_short_handshake).is_err());

        let mut missing_extension_length = server_hello(&[]);
        missing_extension_length[8] = 38;
        assert!(
            parse_npn_protocols(&missing_extension_length)
                .unwrap()
                .is_empty()
        );

        let mut extension_data_overrun = server_hello(&npn_extension(&[0x02, b'h']));
        extension_data_overrun[52] = 0x03;
        assert!(parse_npn_protocols(&extension_data_overrun).is_err());

        let invalid_utf8 = server_hello(&npn_extension(&[0x01, 0xff]));
        assert!(parse_npn_protocols(&invalid_utf8).is_err());

        let mut extension_length_mismatch = server_hello(&npn_extension(&[0x01, b'h']));
        extension_length_mismatch[48] = 0;
        assert!(parse_npn_protocols(&extension_length_mismatch).is_err());

        let truncated_extension_header = server_hello(&[0x33, 0x74, 0x00, 0x00, 0xaa]);
        assert!(parse_npn_protocols(&truncated_extension_header).is_err());

        let mut zero_protocol_name = Vec::from([0x00]);
        let response = server_hello(&npn_extension(&zero_protocol_name));
        assert!(parse_npn_protocols(&response).is_err());

        zero_protocol_name[0] = 2;
        let response = server_hello(&npn_extension(&zero_protocol_name));
        assert!(parse_npn_protocols(&response).is_err());
    }

    #[test]
    fn stops_parsing_protocol_names_at_the_configured_limit() {
        let mut list = Vec::new();
        for _ in 0..=MAX_PROTOCOLS {
            list.extend_from_slice(&[1, b'x']);
        }

        let mut protocols = Vec::new();
        parse_protocol_list(&list, 0, list.len(), &mut protocols)
            .expect("protocol list should stop at its configured limit");

        assert_eq!(protocols.len(), MAX_PROTOCOLS);
    }
}
