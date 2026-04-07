use super::{HandshakeParseResult, PreHandshakeScanner};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use crate::error::TlsError;

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
                break;
            }

            let content_type = data[offset];
            let record_length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            offset += 5;

            if offset + record_length > data.len() {
                break;
            }

            if content_type != 0x16 {
                offset += record_length;
                continue;
            }

            let record_end = offset + record_length;
            while offset < record_end {
                if offset + 4 > data.len() {
                    break;
                }

                let handshake_type = data[offset];
                let handshake_length =
                    u32::from_be_bytes([0, data[offset + 1], data[offset + 2], data[offset + 3]])
                        as usize;

                offset += 4;
                if offset + handshake_length > data.len() {
                    break;
                }

                match handshake_type {
                    0x02 => {
                        if handshake_length >= 38 {
                            let version_maj = data[offset];
                            let version_min = data[offset + 1];
                            protocol_version = Some(format!("{}.{}", version_maj - 2, version_min));

                            let cipher_offset = offset + 34;
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

                                if cert_offset + cert_length <= data.len() {
                                    let cert_der = &data[cert_offset..cert_offset + cert_length];
                                    certificate_data = self.parse_certificate(cert_der).ok();
                                }
                            }
                        }
                    }
                    _ => {}
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
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
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
