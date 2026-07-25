use crate::Result;
use crate::constants::CONTENT_TYPE_HANDSHAKE;

use super::{TICKETBLEED_SESSION_ID_MARKER, read_u16_at, read_u24_at};

pub(super) fn detect_memory_leak(response: &[u8]) -> Result<bool> {
    Ok(extract_session_id(response)?.is_some_and(|session_id| {
        session_id.len() > TICKETBLEED_SESSION_ID_MARKER.len()
            && session_id.starts_with(&TICKETBLEED_SESSION_ID_MARKER)
    }))
}

fn extract_session_id(response: &[u8]) -> Result<Option<&[u8]>> {
    let mut offset = 0usize;
    while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= response.len()) {
        let record_len_offset =
            offset
                .checked_add(3)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "Ticketbleed ServerHello record length offset overflow".to_string(),
                })?;
        let record_len = read_u16_at(response, record_len_offset)
            .map(usize::from)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "Ticketbleed ServerHello record length truncated".to_string(),
            })?;
        let record_end =
            header_end
                .checked_add(record_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "Ticketbleed ServerHello record length overflow".to_string(),
                })?;
        if record_end > response.len() {
            return Err(crate::TlsError::ParseError {
                message: "Ticketbleed ServerHello record length exceeds available data".to_string(),
            });
        }
        if response.get(offset) == Some(&CONTENT_TYPE_HANDSHAKE) {
            let mut hs_start = header_end;
            while let Some(hs_body_start) = hs_start.checked_add(4).filter(|&end| end <= record_end)
            {
                let hs_len = read_u24_at(response, hs_start + 1).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello handshake length truncated".to_string(),
                    }
                })?;
                let hs_end = hs_body_start.checked_add(hs_len).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello handshake length overflow".to_string(),
                    }
                })?;
                if hs_end > record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello handshake length exceeds record"
                            .to_string(),
                    });
                }
                if response.get(hs_start) != Some(&0x02) {
                    hs_start = hs_end;
                    continue;
                }

                let session_id_len_pos = hs_body_start.checked_add(2 + 32).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello session ID offset overflow".to_string(),
                    }
                })?;
                let session_id_len = response
                    .get(session_id_len_pos)
                    .copied()
                    .map(usize::from)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello session ID length truncated".to_string(),
                    })?;
                let session_id_start = session_id_len_pos.checked_add(1).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello session ID start overflow".to_string(),
                    }
                })?;
                let session_id_end =
                    session_id_start
                        .checked_add(session_id_len)
                        .ok_or_else(|| crate::TlsError::ParseError {
                            message: "Ticketbleed ServerHello session ID length overflow"
                                .to_string(),
                        })?;
                if session_id_end <= hs_end {
                    return response.get(session_id_start..session_id_end).map_or_else(
                        || {
                            Err(crate::TlsError::ParseError {
                                message: "Ticketbleed ServerHello session ID truncated".to_string(),
                            })
                        },
                        |session_id| Ok(Some(session_id)),
                    );
                }
                return Err(crate::TlsError::ParseError {
                    message: "Ticketbleed ServerHello session ID exceeds handshake".to_string(),
                });
            }
            if hs_start != record_end {
                return Err(crate::TlsError::ParseError {
                    message: "Ticketbleed ServerHello handshake header truncated".to_string(),
                });
            }
        }
        offset = record_end;
    }
    if offset != response.len() {
        if offset == 0 && response.first() != Some(&CONTENT_TYPE_HANDSHAKE) {
            return Ok(None);
        }
        return Err(crate::TlsError::ParseError {
            message: "Ticketbleed ServerHello record header truncated".to_string(),
        });
    }
    Ok(None)
}
