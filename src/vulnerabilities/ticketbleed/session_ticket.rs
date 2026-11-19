use crate::Result;
use crate::utils::byte_parse::{read_u16_at, read_u24_at};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, 0x03, 0x03];
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn message(kind: u8, body: &[u8]) -> Vec<u8> {
        let length = body.len();
        let mut bytes = vec![
            kind,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ];
        bytes.extend_from_slice(body);
        bytes
    }

    fn ticket(ticket: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(ticket);
        record(0x16, &message(0x04, &body))
    }

    #[test]
    fn detects_empty_and_nonempty_new_session_tickets() {
        assert!(is_present(&ticket(&[])).unwrap());
        assert_eq!(extract(&ticket(&[])).unwrap(), None);
        assert!(is_present(&ticket(b"ticket-data")).unwrap());
        assert_eq!(
            extract(&ticket(b"ticket-data")).unwrap(),
            Some(b"ticket-data".to_vec())
        );
    }

    #[test]
    fn skips_unrelated_records_and_handshake_messages() {
        assert_eq!(extract(&record(0x15, &[])).unwrap(), None);
        assert!(!is_present(&record(0x15, &[])).unwrap());

        let response = record(0x16, &message(0x02, &[0; 3]));
        assert_eq!(extract(&response).unwrap(), None);
        assert!(!is_present(&response).unwrap());
    }

    #[test]
    fn rejects_truncated_record_and_handshake_lengths() {
        assert!(extract(&[0x16, 0x03]).is_err());
        assert!(is_present(&[0x16, 0x03]).is_err());

        let truncated_header = record(0x16, &[0x04, 0]);
        assert!(extract(&truncated_header).is_err());
        assert!(is_present(&truncated_header).is_err());

        let invalid_length = record(0x16, &[0x04, 0, 0, 5, 0]);
        assert!(extract(&invalid_length).is_err());
        assert!(is_present(&invalid_length).is_err());
    }

    #[test]
    fn rejects_truncated_or_oversized_ticket_data() {
        let short_body = record(0x16, &message(0x04, &[0; 5]));
        assert!(extract(&short_body).is_err());

        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&2u16.to_be_bytes());
        body.push(0xaa);
        let truncated_ticket = record(0x16, &message(0x04, &body));
        assert!(extract(&truncated_ticket).is_err());
    }
}
