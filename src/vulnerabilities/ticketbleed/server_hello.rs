use crate::Result;
use crate::constants::CONTENT_TYPE_HANDSHAKE;
use crate::utils::byte_parse::{read_u16_at, read_u24_at};

use super::client_hello::SESSION_ID_MARKER;

pub(super) fn detect_memory_leak(response: &[u8]) -> Result<bool> {
    Ok(extract_session_id(response)?.is_some_and(|session_id| {
        session_id.len() > SESSION_ID_MARKER.len() && session_id.starts_with(&SESSION_ID_MARKER)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, 0x03, 0x03];
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        let length = body.len();
        let mut bytes = vec![
            kind,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ];
        bytes.extend_from_slice(body);
        record(CONTENT_TYPE_HANDSHAKE, &bytes)
    }

    fn parse_error(response: &[u8], expected: &str) {
        let error = detect_memory_leak(response).expect_err("malformed ServerHello must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }

    #[test]
    fn skips_non_handshake_records_and_other_handshake_messages() {
        let mut response = record(0x15, &[]);
        let server_hello = [handshake(0x0b, &[]), handshake(0x02, &[0; 35])].concat();
        response.extend_from_slice(&server_hello);

        assert!(!detect_memory_leak(&response).unwrap());
        assert!(!detect_memory_leak(&record(0x15, &[])).unwrap());
    }

    #[test]
    fn detects_only_session_ids_that_extend_the_client_marker() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push((SESSION_ID_MARKER.len() + 1) as u8);
        body.extend_from_slice(&SESSION_ID_MARKER);
        body.push(0xaa);
        assert!(detect_memory_leak(&handshake(0x02, &body)).unwrap());

        let mut marker_only_body = vec![0x03, 0x03];
        marker_only_body.extend_from_slice(&[0; 32]);
        marker_only_body.push(SESSION_ID_MARKER.len() as u8);
        marker_only_body.extend_from_slice(&SESSION_ID_MARKER);
        assert!(!detect_memory_leak(&handshake(0x02, &marker_only_body)).unwrap());
    }

    #[test]
    fn rejects_truncated_record_and_handshake_headers() {
        assert!(!detect_memory_leak(&[0x15, 0x03]).unwrap());
        parse_error(&[0x16, 0x03], "record header truncated");
        parse_error(
            &record(CONTENT_TYPE_HANDSHAKE, &[0x02, 0]),
            "handshake header truncated",
        );
        parse_error(
            &record(CONTENT_TYPE_HANDSHAKE, &[0x02, 0, 0, 10]),
            "handshake length exceeds record",
        );
    }

    #[test]
    fn rejects_server_hello_without_session_id_length_or_complete_session_id() {
        parse_error(&handshake(0x02, &[0; 34]), "session ID length truncated");
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(3);
        body.extend_from_slice(&[1, 2]);
        parse_error(&handshake(0x02, &body), "session ID exceeds handshake");
    }
}
