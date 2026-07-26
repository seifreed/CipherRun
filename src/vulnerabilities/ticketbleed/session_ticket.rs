use crate::Result;

use super::parse::{read_u16_at, read_u24_at};

pub(super) fn extract(response: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut offset = 0usize;
    while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= response.len()) {
        let header = response
            .get(offset..header_end)
            .and_then(|header| <&[u8; 5]>::try_from(header).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "Ticketbleed ticket TLS record header truncated".to_string(),
            })?;
        let [content_type, _, _, len_high, len_low] = *header;
        let record_len = u16::from_be_bytes([len_high, len_low]) as usize;
        let record_end =
            header_end
                .checked_add(record_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "Ticketbleed ticket TLS record length overflow".to_string(),
                })?;
        if record_end > response.len() {
            return Err(crate::TlsError::ParseError {
                message: "Ticketbleed ticket TLS record length exceeds available data".to_string(),
            });
        }
        if content_type == 0x16 {
            let mut hs_start = header_end;
            while let Some(hs_body_start) = hs_start.checked_add(4).filter(|&end| end <= record_end)
            {
                let hs_len_offset =
                    hs_start
                        .checked_add(1)
                        .ok_or_else(|| crate::TlsError::ParseError {
                            message: "Ticketbleed ticket handshake length offset overflow"
                                .to_string(),
                        })?;
                let hs_len = read_u24_at(response, hs_len_offset).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ticket handshake length truncated".to_string(),
                    }
                })?;
                let hs_end = hs_body_start.checked_add(hs_len).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ticket handshake length overflow".to_string(),
                    }
                })?;
                if hs_end > record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed ticket handshake length exceeds record".to_string(),
                    });
                }
                if response.get(hs_start) != Some(&0x04) {
                    hs_start = hs_end;
                    continue;
                }

                let ticket_len_offset =
                    hs_body_start
                        .checked_add(4)
                        .ok_or_else(|| crate::TlsError::ParseError {
                            message: "Ticketbleed ticket lifetime offset overflow".to_string(),
                        })?;
                let ticket_len_end = ticket_len_offset.checked_add(2).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ticket length offset overflow".to_string(),
                    }
                })?;
                if ticket_len_end > hs_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed ticket length truncated".to_string(),
                    });
                }
                let ticket_len = read_u16_at(response, ticket_len_offset)
                    .map(usize::from)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Ticketbleed ticket length truncated".to_string(),
                    })?;

                let ticket_start = ticket_len_end;
                let ticket_end = ticket_start.checked_add(ticket_len).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed ticket length overflow".to_string(),
                    }
                })?;
                if ticket_len == 0 {
                    return Ok(None);
                }
                if ticket_end > hs_end || ticket_end > record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed ticket data exceeds handshake".to_string(),
                    });
                }
                return response
                    .get(ticket_start..ticket_end)
                    .map(|ticket| Ok(Some(ticket.to_vec())))
                    .unwrap_or_else(|| {
                        Err(crate::TlsError::ParseError {
                            message: "Ticketbleed ticket data truncated".to_string(),
                        })
                    });
            }
            if hs_start != record_end {
                return Err(crate::TlsError::ParseError {
                    message: "Ticketbleed ticket handshake header truncated".to_string(),
                });
            }
        }
        offset = record_end;
    }
    if offset != response.len() {
        if offset == 0 && response.first() != Some(&0x16) {
            return Ok(None);
        }
        return Err(crate::TlsError::ParseError {
            message: "Ticketbleed ticket TLS record header truncated".to_string(),
        });
    }
    Ok(None)
}

pub(super) fn is_present(response: &[u8]) -> Result<bool> {
    let mut offset = 0usize;
    while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= response.len()) {
        let header = response
            .get(offset..header_end)
            .and_then(|header| <&[u8; 5]>::try_from(header).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "Ticketbleed TLS record header truncated".to_string(),
            })?;
        let [content_type, _, _, len_high, len_low] = *header;
        let record_len = u16::from_be_bytes([len_high, len_low]) as usize;
        let record_end =
            header_end
                .checked_add(record_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "Ticketbleed TLS record length overflow".to_string(),
                })?;
        if record_end > response.len() {
            return Err(crate::TlsError::ParseError {
                message: "Ticketbleed TLS record length exceeds available data".to_string(),
            });
        }
        if content_type == 0x16 {
            let mut hs_start = header_end;
            while let Some(hs_body_start) = hs_start.checked_add(4).filter(|&end| end <= record_end)
            {
                let hs_len_offset =
                    hs_start
                        .checked_add(1)
                        .ok_or_else(|| crate::TlsError::ParseError {
                            message: "Ticketbleed handshake length offset overflow".to_string(),
                        })?;
                let hs_len = read_u24_at(response, hs_len_offset).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed handshake length truncated".to_string(),
                    }
                })?;
                let hs_end = hs_body_start.checked_add(hs_len).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "Ticketbleed handshake length overflow".to_string(),
                    }
                })?;
                if hs_end > record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed handshake length exceeds record".to_string(),
                    });
                }
                if response.get(hs_start) == Some(&0x04) {
                    return Ok(true);
                }
                hs_start = hs_end;
            }
            if hs_start != record_end {
                return Err(crate::TlsError::ParseError {
                    message: "Ticketbleed NewSessionTicket header truncated".to_string(),
                });
            }
        }
        offset = record_end;
    }
    if offset != response.len() {
        if offset == 0 && response.first() != Some(&0x16) {
            return Err(crate::TlsError::ParseError {
                message: "Ticketbleed response is not a handshake record".to_string(),
            });
        }
        return Err(crate::TlsError::ParseError {
            message: "Ticketbleed TLS record header truncated".to_string(),
        });
    }
    Ok(false)
}
