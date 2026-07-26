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
}
