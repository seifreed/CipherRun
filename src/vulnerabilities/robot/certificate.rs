use crate::Result;
use crate::vulnerabilities::bytes::read_u24_at;
use openssl::x509::X509;

/// Parse the server handshake buffer to find the Certificate message and return the RSA
/// modulus length in bytes.
pub(super) fn extract_rsa_key_len(buffer: &[u8]) -> Result<usize> {
    let mut offset = 0usize;
    while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= buffer.len()) {
        let Some(header) = buffer
            .get(offset..header_end)
            .and_then(|header| <&[u8; 5]>::try_from(header).ok())
        else {
            break;
        };
        let [record_type, _, _, len_high, len_low] = *header;
        let record_len = usize::from(u16::from_be_bytes([len_high, len_low]));
        let Some(record_end) = header_end.checked_add(record_len) else {
            return Err(crate::TlsError::ParseError {
                message: "ROBOT TLS record length overflow".to_string(),
            });
        };
        if record_end > buffer.len() {
            return Err(crate::TlsError::ParseError {
                message: "ROBOT TLS record length exceeds available data".to_string(),
            });
        }
        if record_type == 0x16 {
            let mut hoff = header_end;
            while let Some(hs_body_start) = hoff.checked_add(4).filter(|&end| end <= record_end) {
                let Some(hs_type) = buffer.get(hoff).copied() else {
                    break;
                };
                let Some(hs_len_offset) = hoff.checked_add(1) else {
                    break;
                };
                let Some(hs_len) = read_u24_at(buffer, hs_len_offset) else {
                    break;
                };
                let Some(hs_end) = hs_body_start.checked_add(hs_len) else {
                    return Err(crate::TlsError::ParseError {
                        message: "ROBOT handshake length overflow".to_string(),
                    });
                };
                if hs_end > record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "ROBOT handshake length exceeds record".to_string(),
                    });
                }
                if hs_type == 0x0b {
                    return rsa_key_len_from_certificate(buffer, hs_body_start, hs_end, hs_len);
                }
                hoff = hs_end;
            }
            if hoff != record_end {
                return Err(crate::TlsError::ParseError {
                    message: "ROBOT handshake header truncated".to_string(),
                });
            }
        }
        offset = record_end;
    }
    Err(crate::TlsError::ParseError {
        message: "Unable to determine RSA key length from server handshake".to_string(),
    })
}

fn rsa_key_len_from_certificate(
    buffer: &[u8],
    hs_body_start: usize,
    hs_end: usize,
    hs_len: usize,
) -> Result<usize> {
    if hs_len < 6 {
        return Err(crate::TlsError::ParseError {
            message: "ROBOT Certificate message too short".to_string(),
        });
    }
    let cert_list_len =
        read_u24_at(buffer, hs_body_start).ok_or_else(|| crate::TlsError::ParseError {
            message: "ROBOT Certificate list length truncated".to_string(),
        })?;
    let cert_list_start =
        hs_body_start
            .checked_add(3)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "ROBOT Certificate list offset overflow".to_string(),
            })?;
    let cert_list_end =
        cert_list_start
            .checked_add(cert_list_len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "ROBOT Certificate list length overflow".to_string(),
            })?;
    if cert_list_end != hs_end {
        return Err(crate::TlsError::ParseError {
            message: "ROBOT Certificate list length mismatch".to_string(),
        });
    }
    let cert_len =
        read_u24_at(buffer, cert_list_start).ok_or_else(|| crate::TlsError::ParseError {
            message: "ROBOT Certificate entry length truncated".to_string(),
        })?;
    let cert_start = cert_list_start
        .checked_add(3)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "ROBOT Certificate entry offset overflow".to_string(),
        })?;
    let cert_end = cert_start
        .checked_add(cert_len)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "ROBOT Certificate length overflow".to_string(),
        })?;
    if cert_end > cert_list_end {
        return Err(crate::TlsError::ParseError {
            message: "ROBOT Certificate length exceeds list".to_string(),
        });
    }
    let cert_der = buffer
        .get(cert_start..cert_end)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "ROBOT Certificate DER truncated".to_string(),
        })?;
    let cert = X509::from_der(cert_der).map_err(|error| crate::TlsError::ParseError {
        message: format!("ROBOT Certificate DER parse failed: {error}"),
    })?;
    let pkey = cert
        .public_key()
        .map_err(|error| crate::TlsError::ParseError {
            message: format!("ROBOT Certificate public key parse failed: {error}"),
        })?;
    let rsa = pkey.rsa().map_err(|error| crate::TlsError::ParseError {
        message: format!("ROBOT Certificate RSA key parse failed: {error}"),
    })?;
    usize::try_from(rsa.n().num_bytes()).map_err(|_| crate::TlsError::ParseError {
        message: "RSA key length does not fit in usize".to_string(),
    })
}
