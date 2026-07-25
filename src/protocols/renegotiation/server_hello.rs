use super::bytes;
use crate::Result;
use crate::constants::{CONTENT_TYPE_HANDSHAKE, EXTENSION_RENEGOTIATION_INFO};

pub(super) fn has_renegotiation_info_extension(response: &[u8]) -> Result<bool> {
    const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

    if response.first() != Some(&CONTENT_TYPE_HANDSHAKE)
        || bytes::read_u8_at(response, 5, "ServerHello handshake type")?
            != HANDSHAKE_TYPE_SERVER_HELLO
    {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello handshake type missing or invalid".to_string(),
        });
    }

    if response.len() < 44 {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before minimum renegotiation extension length"
                .to_string(),
        });
    }

    let record_len = bytes::read_u16_at(response, 3, "TLS record length")? as usize;
    let record_end = 5 + record_len;
    if record_end > response.len() {
        return Err(crate::TlsError::ParseError {
            message: "TLS record length exceeds available data".to_string(),
        });
    }
    let handshake_len = bytes::read_u24_at(response, 6, "ServerHello handshake length")?;
    let handshake_end =
        9usize
            .checked_add(handshake_len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "ServerHello handshake length overflow".to_string(),
            })?;
    if handshake_end > record_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello handshake length exceeds record length".to_string(),
        });
    }

    let sid_len_offset = 5 + 4 + 2 + 32;
    if sid_len_offset >= handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before session_id_len".to_string(),
        });
    }
    let sid_len =
        bytes::read_u8_at(response, sid_len_offset, "ServerHello session_id_len")? as usize;

    let ext_len_offset = sid_len_offset
        .checked_add(1)
        .and_then(|offset| offset.checked_add(sid_len))
        .and_then(|offset| offset.checked_add(2 + 1))
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "ServerHello extensions offset overflow".to_string(),
        })?;
    if ext_len_offset == handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before extensions length".to_string(),
        });
    }
    let ext_start = ext_len_offset
        .checked_add(2)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "ServerHello extensions length overflow".to_string(),
        })?;
    if ext_start > handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello truncated before extensions length".to_string(),
        });
    }
    let ext_total =
        bytes::read_u16_at(response, ext_len_offset, "ServerHello extensions length")? as usize;

    let ext_end = ext_start
        .checked_add(ext_total)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "ServerHello extension block length overflow".to_string(),
        })?;
    if ext_end > handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extension block extends beyond declared length".to_string(),
        });
    }
    if ext_end != handshake_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extension block contains trailing bytes".to_string(),
        });
    }
    if ext_start >= ext_end {
        return Ok(false);
    }

    let mut pos = ext_start;
    while let Some(ext_header_end) = pos.checked_add(4).filter(|&end| end <= ext_end) {
        let ext_type = bytes::read_u16_at(response, pos, "ServerHello extension type")?;
        let ext_len_offset = pos
            .checked_add(2)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "ServerHello extension length offset overflow".to_string(),
            })?;
        let ext_len =
            bytes::read_u16_at(response, ext_len_offset, "ServerHello extension length")? as usize;
        let ext_data_end =
            ext_header_end
                .checked_add(ext_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "ServerHello extension data length overflow".to_string(),
                })?;
        if ext_data_end > ext_end {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated in renegotiation extension data".to_string(),
            });
        }
        if ext_type == EXTENSION_RENEGOTIATION_INFO {
            return Ok(true);
        }
        pos = ext_data_end;
    }
    if pos != ext_end {
        return Err(crate::TlsError::ParseError {
            message: "ServerHello extension block contains trailing bytes".to_string(),
        });
    }
    Ok(false)
}
