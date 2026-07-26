use crate::Result;

use super::parse::read_u16_at;

fn read_u24_at(data: &[u8], offset: usize) -> Option<usize> {
    let bytes = data.get(offset..offset.checked_add(3)?)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

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

    let Some(record_len) = read_u16_at(data, 3).map(usize::from) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before record length".to_string(),
        });
    };
    let Some(record_end) = 5usize.checked_add(record_len) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello record length overflow".to_string(),
        });
    };
    if record_end > data.len() {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello record length extends beyond buffer".to_string(),
        });
    }
    let Some(hs_len) = read_u24_at(data, 6) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before handshake length".to_string(),
        });
    };
    let Some(hs_end) = 9usize.checked_add(hs_len) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello handshake length overflow".to_string(),
        });
    };
    if hs_end > record_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello handshake length exceeds record length".to_string(),
        });
    }

    let Some(sid_len) = data.get(43).copied().map(usize::from) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before session_id_len".to_string(),
        });
    };
    if sid_len > 32 {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello session_id_length exceeds TLS maximum".to_string(),
        });
    }
    let Some(ext_offset) = 44usize
        .checked_add(sid_len)
        .and_then(|offset| offset.checked_add(2 + 1))
    else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extensions offset overflow".to_string(),
        });
    };
    if ext_offset == hs_end {
        return Ok(false);
    }

    let Some(ext_start) = ext_offset.checked_add(2) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extensions length overflow".to_string(),
        });
    };
    if ext_start > hs_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before extensions length".to_string(),
        });
    }

    let Some(ext_total_len) = read_u16_at(data, ext_offset).map(usize::from) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before extensions length".to_string(),
        });
    };
    let Some(ext_end) = ext_start.checked_add(ext_total_len) else {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extension block length overflow".to_string(),
        });
    };
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
    while let Some(ext_header_end) = pos.checked_add(4).filter(|&end| end <= ext_end) {
        let Some(ext_type) = read_u16_at(data, pos) else {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension type truncated".to_string(),
            });
        };
        let Some(ext_len_offset) = pos.checked_add(2) else {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension length offset overflow".to_string(),
            });
        };
        let Some(ext_len) = read_u16_at(data, ext_len_offset).map(usize::from) else {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension length truncated".to_string(),
            });
        };
        pos = ext_header_end;

        let Some(next_pos) = pos.checked_add(ext_len) else {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension data length overflow".to_string(),
            });
        };
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
