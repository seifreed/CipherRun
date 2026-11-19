use crate::Result;
use crate::utils::byte_parse::read_u24_at;
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

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509Builder, X509NameBuilder},
    };

    fn record(payload: &[u8]) -> Vec<u8> {
        record_with_type(0x16, payload)
    }

    fn record_with_type(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, 0x03, 0x03];
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
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

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        record(&handshake_message(kind, body))
    }

    fn certificate_body(certificate_list: &[u8]) -> Vec<u8> {
        let length = certificate_list.len();
        let mut body = vec![(length >> 16) as u8, (length >> 8) as u8, length as u8];
        body.extend_from_slice(certificate_list);
        body
    }

    fn certificate(key: PKey<openssl::pkey::Private>) -> Vec<u8> {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "robot.test").unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    fn certificate_entry(der: &[u8]) -> Vec<u8> {
        let mut entry = vec![
            (der.len() >> 16) as u8,
            (der.len() >> 8) as u8,
            der.len() as u8,
        ];
        entry.extend_from_slice(der);
        certificate_body(&entry)
    }

    fn parse_error(bytes: &[u8], expected: &str) {
        let error = extract_rsa_key_len(bytes).expect_err("malformed certificate must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }

    #[test]
    fn extracts_rsa_modulus_length_from_certificate_message() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let body = certificate_entry(&certificate(key));
        let mut bytes = record_with_type(0x15, &[]);
        bytes.extend_from_slice(&record(
            &[handshake_message(0x02, &[]), handshake_message(0x0b, &body)].concat(),
        ));
        assert_eq!(extract_rsa_key_len(&bytes).unwrap(), 256);
    }

    #[test]
    fn rejects_record_and_handshake_length_errors() {
        parse_error(&[0x16, 0x03, 0x03, 0, 4, 1], "record length exceeds");
        parse_error(&record(&[0x0b, 0]), "handshake header truncated");
        parse_error(
            &record(&[0x02, 0, 0, 4, 0]),
            "handshake length exceeds record",
        );
        parse_error(
            &handshake(0x02, &[0, 0, 0]),
            "Unable to determine RSA key length",
        );
    }

    #[test]
    fn rejects_invalid_certificate_message_lengths() {
        parse_error(&handshake(0x0b, &[0; 5]), "Certificate message too short");
        parse_error(
            &handshake(0x0b, &[0, 0, 2, 0, 0, 0]),
            "Certificate list length mismatch",
        );
        parse_error(
            &handshake(0x0b, &certificate_body(&[0, 0, 1])),
            "Certificate length exceeds list",
        );
        parse_error(
            &handshake(0x0b, &certificate_body(&[0, 0, 1, 0xff])),
            "Certificate DER parse failed",
        );
    }

    #[test]
    fn rejects_non_rsa_certificate_keys() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec_key).unwrap();
        let body = certificate_entry(&certificate(key));
        parse_error(&handshake(0x0b, &body), "Certificate RSA key parse failed");
    }
}
