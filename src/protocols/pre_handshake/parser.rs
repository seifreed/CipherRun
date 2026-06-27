use super::{HandshakeParseResult, PreHandshakeScanner};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use crate::error::TlsError;
use tracing::trace;

impl PreHandshakeScanner {
    fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
        data.get(offset)
            .copied()
            .ok_or_else(|| TlsError::ParseError {
                message: format!("{context} truncated"),
            })
    }

    fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
        let end = offset.checked_add(2).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} length overflow"),
        })?;
        let bytes = data
            .get(offset..end)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24_at(data: &[u8], offset: usize, context: &str) -> Result<usize> {
        let end = offset.checked_add(3).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} length overflow"),
        })?;
        let [high, mid, low] = data
            .get(offset..end)
            .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())
            .ok_or_else(|| TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(((high as usize) << 16) | ((mid as usize) << 8) | low as usize)
    }

    fn slice_range<'a>(
        data: &'a [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> Result<&'a [u8]> {
        let end = start.checked_add(len).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} length overflow"),
        })?;
        data.get(start..end).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} truncated"),
        })
    }

    pub(super) fn parse_handshake_response(&self, data: &[u8]) -> Result<HandshakeParseResult> {
        let mut offset = 0usize;
        let mut certificate_data = None;
        let mut server_hello_data = None;
        let mut protocol_version = None;
        let mut cipher_suite = None;
        let mut compression_method = None;

        while offset < data.len() {
            let header_end = offset.checked_add(5).ok_or_else(|| TlsError::ParseError {
                message: "TLS record header length overflow".to_string(),
            })?;
            if header_end > data.len() {
                return Err(TlsError::ParseError {
                    message: "TLS record header truncated".to_string(),
                });
            }

            let content_type = Self::read_u8_at(data, offset, "TLS record type")?;
            let record_len_offset = offset.checked_add(3).ok_or_else(|| TlsError::ParseError {
                message: "TLS record length offset overflow".to_string(),
            })?;
            let record_length =
                Self::read_u16_at(data, record_len_offset, "TLS record length")? as usize;
            offset = header_end;

            let record_end =
                offset
                    .checked_add(record_length)
                    .ok_or_else(|| TlsError::ParseError {
                        message: "TLS record length overflow".to_string(),
                    })?;
            if record_end > data.len() {
                return Err(TlsError::ParseError {
                    message: "TLS record length exceeds available data".to_string(),
                });
            }

            if content_type != 0x16 {
                offset += record_length;
                continue;
            }

            while offset < record_end {
                let handshake_body_start =
                    offset.checked_add(4).ok_or_else(|| TlsError::ParseError {
                        message: "Handshake header length overflow".to_string(),
                    })?;
                if handshake_body_start > record_end {
                    return Err(TlsError::ParseError {
                        message: "Handshake header truncated".to_string(),
                    });
                }

                let handshake_type = Self::read_u8_at(data, offset, "Handshake type")?;
                let handshake_len_offset =
                    offset.checked_add(1).ok_or_else(|| TlsError::ParseError {
                        message: "Handshake length offset overflow".to_string(),
                    })?;
                let handshake_length =
                    Self::read_u24_at(data, handshake_len_offset, "Handshake length")?;

                offset = handshake_body_start;
                let handshake_end =
                    offset
                        .checked_add(handshake_length)
                        .ok_or_else(|| TlsError::ParseError {
                            message: "Handshake length overflow".to_string(),
                        })?;
                if handshake_end > record_end {
                    return Err(TlsError::ParseError {
                        message: "Handshake length exceeds available data".to_string(),
                    });
                }

                match handshake_type {
                    0x02 => {
                        if handshake_length >= 38 {
                            let version = Self::read_u16_at(data, offset, "ServerHello version")?;
                            // Map two-byte version field to canonical name. Arithmetic
                            // on `version_maj - 2` panics on SSLv2 (0x02) and produces
                            // nonsense for non-standard bytes; a match over the u16
                            // covers all real TLS versions safely.
                            protocol_version = Some(match version {
                                0x0002 => "SSL 2.0".to_string(),
                                0x0300 => "SSL 3.0".to_string(),
                                0x0301 => "TLS 1.0".to_string(),
                                0x0302 => "TLS 1.1".to_string(),
                                0x0303 => "TLS 1.2".to_string(),
                                0x0304 => "TLS 1.3".to_string(),
                                v => format!("Unknown (0x{:04x})", v),
                            });

                            // ServerHello body: version(2) + random(32) + sid_len(1) +
                            // session_id(sid_len) + cipher(2) + compression(1).
                            // Cipher lives at `offset + 35 + session_id_len`, not the
                            // fixed `offset + 34` (which skips the sid_len byte).
                            let Some(sid_len_at) = offset.checked_add(34) else {
                                offset = handshake_end;
                                continue;
                            };
                            if sid_len_at < handshake_end {
                                let session_id_len =
                                    Self::read_u8_at(data, sid_len_at, "ServerHello session ID")?
                                        as usize;
                                let Some(cipher_offset) = offset
                                    .checked_add(35)
                                    .and_then(|base| base.checked_add(session_id_len))
                                else {
                                    offset = handshake_end;
                                    continue;
                                };
                                let Some(cipher_end) = cipher_offset.checked_add(2) else {
                                    offset = handshake_end;
                                    continue;
                                };
                                if cipher_end <= handshake_end {
                                    let cipher = Self::read_u16_at(
                                        data,
                                        cipher_offset,
                                        "ServerHello cipher",
                                    )?;
                                    cipher_suite = Some(format!("0x{:04x}", cipher));

                                    let Some(compression_offset) = cipher_offset.checked_add(2)
                                    else {
                                        offset = handshake_end;
                                        continue;
                                    };
                                    let Some(compression_end) = cipher_offset.checked_add(3) else {
                                        offset = handshake_end;
                                        continue;
                                    };
                                    if compression_end <= handshake_end {
                                        compression_method = Some(Self::read_u8_at(
                                            data,
                                            compression_offset,
                                            "ServerHello compression",
                                        )?);
                                    }
                                }
                            }

                            server_hello_data = Some(
                                Self::slice_range(
                                    data,
                                    offset,
                                    handshake_length,
                                    "ServerHello body",
                                )?
                                .to_vec(),
                            );
                        }
                    }
                    0x0b => {
                        if handshake_length >= 3 {
                            let certs_length =
                                Self::read_u24_at(data, offset, "Certificate list length")?;

                            // Prevent integer overflow/wraparound on malicious input
                            if certs_length > handshake_end - offset - 3 {
                                return Err(TlsError::ParseError {
                                    message: "Certificate list length exceeds available data"
                                        .to_string(),
                                });
                            }

                            let certs_start =
                                offset.checked_add(3).ok_or_else(|| TlsError::ParseError {
                                    message: "Certificate list offset overflow".to_string(),
                                })?;
                            let mut cert_offset = certs_start;
                            let certs_end =
                                certs_start.checked_add(certs_length).ok_or_else(|| {
                                    TlsError::ParseError {
                                        message: "Certificate list length overflow".to_string(),
                                    }
                                })?;

                            if certs_end != handshake_end {
                                return Err(TlsError::ParseError {
                                    message: "Certificate message contains trailing bytes"
                                        .to_string(),
                                });
                            }

                            let mut parse_leaf = certificate_data.is_none();
                            while cert_offset < certs_end {
                                if cert_offset.checked_add(3).is_none_or(|end| end > certs_end) {
                                    return Err(TlsError::ParseError {
                                        message: "Certificate entry header truncated".to_string(),
                                    });
                                }
                                let cert_length =
                                    Self::read_u24_at(data, cert_offset, "Certificate length")?;
                                cert_offset = cert_offset.checked_add(3).ok_or_else(|| {
                                    TlsError::ParseError {
                                        message: "Certificate offset overflow".to_string(),
                                    }
                                })?;

                                let cert_end =
                                    cert_offset.checked_add(cert_length).ok_or_else(|| {
                                        TlsError::ParseError {
                                            message: "Certificate length overflow".to_string(),
                                        }
                                    })?;
                                if cert_end > certs_end {
                                    return Err(TlsError::ParseError {
                                        message: "Certificate length exceeds list".to_string(),
                                    });
                                }
                                let cert_der = Self::slice_range(
                                    data,
                                    cert_offset,
                                    cert_length,
                                    "Certificate DER",
                                )?;
                                if parse_leaf {
                                    certificate_data = Some(self.parse_certificate(cert_der)?);
                                    parse_leaf = false;
                                }
                                cert_offset = cert_end;
                            }
                        }
                    }
                    _ => {
                        trace!(
                            "Skipping unhandled handshake type: 0x{:02x}",
                            handshake_type
                        );
                    }
                }

                offset = handshake_end;
            }
        }

        Ok(HandshakeParseResult {
            certificate_data,
            server_hello_data,
            protocol_version,
            cipher_suite,
            compression_method,
        })
    }

    fn parse_certificate(&self, der: &[u8]) -> Result<CertificateInfo> {
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(der).map_err(|e| TlsError::ParseError {
            message: format!("Failed to parse certificate: {:?}", e),
        })?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let not_before = cert
            .validity()
            .not_before
            .to_rfc2822()
            .unwrap_or_else(|e| e);
        let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_else(|e| e);
        let serial_number = cert.serial.to_string();

        let mut san = Vec::new();
        if let Some(san_ext) =
            cert.subject_alternative_name()
                .map_err(|e| TlsError::ParseError {
                    message: format!("Failed to parse subject alternative name: {:?}", e),
                })?
        {
            for name in &san_ext.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    san.push(dns.to_string());
                }
            }
        }

        let signature_algorithm = format!("{}", cert.signature_algorithm.algorithm);
        let public_key_algorithm = format!("{}", cert.public_key().algorithm.algorithm);
        let public_key_size = cert
            .public_key()
            .parsed()
            .map(|pk| match pk {
                x509_parser::public_key::PublicKey::RSA(rsa) => Some(rsa.key_size()),
                _ => None,
            })
            .ok()
            .flatten();

        Ok(CertificateInfo {
            subject,
            issuer,
            not_before,
            not_after,
            serial_number,
            san,
            signature_algorithm,
            public_key_algorithm,
            public_key_size,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

    fn test_scanner() -> PreHandshakeScanner {
        PreHandshakeScanner::new(
            crate::utils::network::Target::with_ips(
                "localhost".to_string(),
                443,
                vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            )
            .unwrap(),
        )
    }

    fn handshake_record(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let handshake_len = body.len() as u32;
        let record_len = (4 + body.len()) as u16;
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&record_len.to_be_bytes());
        record.push(handshake_type);
        record.push(((handshake_len >> 16) & 0xff) as u8);
        record.push(((handshake_len >> 8) & 0xff) as u8);
        record.push((handshake_len & 0xff) as u8);
        record.extend_from_slice(body);
        record
    }

    fn cert_with_raw_extension_der(oid: &str, contents: &[u8]) -> Vec<u8> {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "malformed-extension.example.com")
            .unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        let oid = Asn1Object::from_str(oid).unwrap();
        let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
        let extension = X509Extension::new_from_der(&oid, false, &contents).unwrap();
        builder.append_extension(extension).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        builder.build().to_der().unwrap()
    }

    #[test]
    fn test_parse_certificate_rejects_malformed_san() {
        let scanner = test_scanner();
        let der = cert_with_raw_extension_der("2.5.29.17", b"\x05\x00");

        let error = scanner
            .parse_certificate(&der)
            .expect_err("malformed SAN should fail");

        assert!(
            error
                .to_string()
                .contains("Failed to parse subject alternative name")
        );
    }

    #[test]
    fn test_parse_handshake_rejects_certificate_list_beyond_message() {
        let scanner = test_scanner();
        let record = handshake_record(0x0b, &[0x00, 0x00, 0x01]);

        let error = match scanner.parse_handshake_response(&record) {
            Ok(_) => panic!("certificate list past handshake should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("Certificate list length exceeds available data")
        );
    }

    #[test]
    fn test_parse_handshake_rejects_truncated_certificate_entry() {
        let scanner = test_scanner();
        let record = handshake_record(0x0b, &[0x00, 0x00, 0x05, 0x00, 0x00, 0x04, 0x00, 0x00]);

        let error = match scanner.parse_handshake_response(&record) {
            Ok(_) => panic!("truncated certificate entry should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("Certificate length exceeds list")
        );
    }

    #[test]
    fn test_parse_handshake_rejects_certificate_trailing_bytes() {
        let scanner = test_scanner();
        let record = handshake_record(0x0b, &[0x00, 0x00, 0x00, 0xff]);

        let error = match scanner.parse_handshake_response(&record) {
            Ok(_) => panic!("certificate trailing bytes should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("Certificate message contains trailing bytes")
        );
    }

    #[test]
    fn test_parse_handshake_rejects_trailing_bytes_after_first_certificate() {
        let scanner = test_scanner();
        let cert = cert_with_raw_extension_der("1.2.3.4", b"\x05\x00");
        let cert_len = cert.len() as u32;
        let list_len = cert.len() as u32 + 4;
        let mut body = Vec::new();
        body.extend_from_slice(&[
            ((list_len >> 16) & 0xff) as u8,
            ((list_len >> 8) & 0xff) as u8,
            (list_len & 0xff) as u8,
            ((cert_len >> 16) & 0xff) as u8,
            ((cert_len >> 8) & 0xff) as u8,
            (cert_len & 0xff) as u8,
        ]);
        body.extend_from_slice(&cert);
        body.push(0xff);
        let record = handshake_record(0x0b, &body);

        let error = match scanner.parse_handshake_response(&record) {
            Ok(_) => panic!("certificate list trailing bytes should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("Certificate entry header truncated")
        );
    }
}
