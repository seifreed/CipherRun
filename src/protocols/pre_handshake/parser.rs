use super::{HandshakeParseResult, PreHandshakeScanner};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use crate::error::TlsError;
use tracing::trace;

impl PreHandshakeScanner {
    pub(super) fn parse_handshake_response(&self, data: &[u8]) -> Result<HandshakeParseResult> {
        let mut offset = 0;
        let mut certificate_data = None;
        let mut server_hello_data = None;
        let mut protocol_version = None;
        let mut cipher_suite = None;
        let mut compression_method = None;

        while offset < data.len() {
            if offset + 5 > data.len() {
                return Err(TlsError::ParseError {
                    message: "TLS record header truncated".to_string(),
                });
            }

            let content_type = data[offset];
            let record_length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            offset += 5;

            if offset + record_length > data.len() {
                return Err(TlsError::ParseError {
                    message: "TLS record length exceeds available data".to_string(),
                });
            }

            if content_type != 0x16 {
                offset += record_length;
                continue;
            }

            let record_end = offset + record_length;
            while offset < record_end {
                if offset + 4 > data.len() {
                    return Err(TlsError::ParseError {
                        message: "Handshake header truncated".to_string(),
                    });
                }

                let handshake_type = data[offset];
                let handshake_length =
                    u32::from_be_bytes([0, data[offset + 1], data[offset + 2], data[offset + 3]])
                        as usize;

                offset += 4;
                if offset + handshake_length > data.len() {
                    return Err(TlsError::ParseError {
                        message: "Handshake length exceeds available data".to_string(),
                    });
                }

                match handshake_type {
                    0x02 => {
                        if handshake_length >= 38 {
                            let version_maj = data[offset];
                            let version_min = data[offset + 1];
                            // Map two-byte version field to canonical name. Arithmetic
                            // on `version_maj - 2` panics on SSLv2 (0x02) and produces
                            // nonsense for non-standard bytes; a match over the u16
                            // covers all real TLS versions safely.
                            protocol_version =
                                Some(match u16::from_be_bytes([version_maj, version_min]) {
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
                            let sid_len_at = offset + 34;
                            if sid_len_at < offset + handshake_length {
                                let session_id_len = data[sid_len_at] as usize;
                                let cipher_offset = offset + 35 + session_id_len;
                                if cipher_offset + 2 <= offset + handshake_length {
                                    let cipher = u16::from_be_bytes([
                                        data[cipher_offset],
                                        data[cipher_offset + 1],
                                    ]);
                                    cipher_suite = Some(format!("0x{:04x}", cipher));

                                    if cipher_offset + 3 <= offset + handshake_length {
                                        compression_method = Some(data[cipher_offset + 2]);
                                    }
                                }
                            }

                            server_hello_data =
                                Some(data[offset..offset + handshake_length].to_vec());
                        }
                    }
                    0x0b => {
                        if handshake_length >= 3 {
                            let certs_length = u32::from_be_bytes([
                                0,
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                            ]) as usize;

                            // Prevent integer overflow/wraparound on malicious input
                            if certs_length > data.len() - offset - 3 {
                                return Err(TlsError::ParseError {
                                    message: "Certificate list length exceeds available data"
                                        .to_string(),
                                });
                            }

                            let mut cert_offset = offset + 3;
                            let certs_end = offset + 3 + certs_length;

                            if cert_offset + 3 <= certs_end && cert_offset + 3 <= data.len() {
                                let cert_length = u32::from_be_bytes([
                                    0,
                                    data[cert_offset],
                                    data[cert_offset + 1],
                                    data[cert_offset + 2],
                                ]) as usize;
                                cert_offset += 3;

                                if cert_offset + cert_length <= certs_end
                                    && cert_offset + cert_length <= data.len()
                                {
                                    let cert_der = &data[cert_offset..cert_offset + cert_length];
                                    certificate_data = Some(self.parse_certificate(cert_der)?);
                                }
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

                offset += handshake_length;
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
        if let Some(san_ext) = cert
            .subject_alternative_name()
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
        let scanner = PreHandshakeScanner::new(crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            443,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
        )
        .unwrap());
        let der = cert_with_raw_extension_der("2.5.29.17", b"\x05\x00");

        let error = scanner
            .parse_certificate(&der)
            .expect_err("malformed SAN should fail");

        assert!(error
            .to_string()
            .contains("Failed to parse subject alternative name"));
    }
}
