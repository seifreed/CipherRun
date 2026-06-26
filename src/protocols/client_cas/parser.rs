use super::{ClientCA, ClientCAsTester};

impl ClientCAsTester {
    pub(super) fn find_certificate_request(
        &self,
        data: &[u8],
    ) -> crate::Result<Option<Vec<ClientCA>>> {
        let mut cert_request = None;
        let mut pos = 0;
        let mut handshake_bytes = Vec::new();

        while pos + 5 <= data.len() {
            let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            if pos + 5 + record_len > data.len() {
                return Err(crate::TlsError::ParseError {
                    message: "TLS record length exceeds available data".to_string(),
                });
            }

            if data[pos] != 0x16 {
                // Skip non-handshake records by reading the full record header + length
                pos += 5 + record_len;
                continue;
            }

            pos += 5;

            handshake_bytes.extend_from_slice(&data[pos..pos + record_len]);
            pos += record_len;
        }

        let mut msg_pos = 0;
        while msg_pos + 4 <= handshake_bytes.len() {
            let msg_type = handshake_bytes[msg_pos];
            let msg_len = ((handshake_bytes[msg_pos + 1] as usize) << 16)
                | ((handshake_bytes[msg_pos + 2] as usize) << 8)
                | handshake_bytes[msg_pos + 3] as usize;
            let msg_end = msg_pos + 4 + msg_len;

            if msg_end > handshake_bytes.len() {
                return Err(crate::TlsError::ParseError {
                    message: "Handshake message length exceeds available data".to_string(),
                });
            }

            if msg_type == 13 {
                cert_request = Some(self.parse_ca_list(&handshake_bytes[msg_pos..msg_end])?);
                break;
            }

            msg_pos = msg_end;
        }

        Ok(cert_request)
    }

    #[cfg(test)]
    pub(super) fn parse_certificate_request(&self, data: &[u8]) -> Vec<ClientCA> {
        self.find_certificate_request(data)
            .expect("certificate request should parse")
            .unwrap_or_default()
    }

    pub(super) fn parse_ca_list(&self, data: &[u8]) -> crate::Result<Vec<ClientCA>> {
        if data.len() < 10 {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest too short".to_string(),
            });
        }

        let mut pos = 4;

        if pos >= data.len() {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest missing certificate types".to_string(),
            });
        }
        let cert_types_len = data[pos] as usize;
        pos += 1;
        let cert_types_end =
            pos.checked_add(cert_types_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "CertificateRequest certificate types length exceeds message"
                        .to_string(),
                })?;
        if cert_types_end > data.len() {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest certificate types length exceeds message".to_string(),
            });
        }
        pos = cert_types_end;

        if pos + 2 > data.len() {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest truncated before signature algorithms".to_string(),
            });
        }
        let sig_algs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let sig_algs_end =
            pos.checked_add(sig_algs_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "CertificateRequest signature algorithms length exceeds message"
                        .to_string(),
                })?;
        if sig_algs_end > data.len() {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest signature algorithms length exceeds message"
                    .to_string(),
            });
        }
        pos = sig_algs_end;

        if pos + 2 > data.len() {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest truncated before CA list".to_string(),
            });
        }

        let ca_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let ca_list_end =
            pos.checked_add(ca_list_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "CertificateRequest CA list length exceeds message".to_string(),
                })?;
        if ca_list_end > data.len() {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest CA list length exceeds message".to_string(),
            });
        }

        let mut cas = Vec::new();
        let ca_data = &data[pos..ca_list_end];
        let mut ca_pos = 0;

        while ca_pos + 2 <= ca_data.len() {
            let dn_len = u16::from_be_bytes([ca_data[ca_pos], ca_data[ca_pos + 1]]) as usize;
            ca_pos += 2;

            if ca_pos + dn_len > ca_data.len() {
                return Err(crate::TlsError::ParseError {
                    message: "CertificateRequest CA distinguished name length exceeds list"
                        .to_string(),
                });
            }

            let dn_data = &ca_data[ca_pos..ca_pos + dn_len];
            let dn_hex = hex::encode(dn_data);
            let (cn, org) = self.extract_dn_fields(dn_data)?;

            cas.push(ClientCA {
                distinguished_name: dn_hex,
                common_name: cn,
                organization: org,
            });

            ca_pos += dn_len;
        }

        Ok(cas)
    }

    pub(super) fn extract_dn_fields(
        &self,
        dn_data: &[u8],
    ) -> crate::Result<(Option<String>, Option<String>)> {
        let mut cn = None;
        let mut org = None;

        // Need at least 10 bytes: 3 for OID prefix + 3 for OID type + 1 for length + 3 min data
        // But we access up to i + 6, so we need i + 6 < dn_data.len()
        for i in 0..dn_data.len().saturating_sub(6) {
            if dn_data[i..].len() >= 9  // Need at least 9 bytes: 3 (OID) + 3 (type) + 1 (len) + 2+ (value)
                && dn_data[i..i + 3] == [0x06, 0x03, 0x55]
                && (dn_data[i + 3..i + 6] == [0x04, 0x03, 0x0c]
                    || dn_data[i + 3..i + 6] == [0x04, 0x03, 0x13])
            {
                let len = dn_data[i + 6] as usize;
                if i + 7 + len <= dn_data.len() {
                    let value =
                        std::str::from_utf8(&dn_data[i + 7..i + 7 + len]).map_err(|error| {
                            crate::TlsError::ParseError {
                                message: format!("Invalid certificate request DN UTF-8: {error}"),
                            }
                        })?;
                    cn = Some(value.to_string());
                }
            }

            if dn_data[i..].len() >= 9
                && dn_data[i..i + 3] == [0x06, 0x03, 0x55]
                && (dn_data[i + 3..i + 6] == [0x04, 0x0a, 0x0c]
                    || dn_data[i + 3..i + 6] == [0x04, 0x0a, 0x13])
            {
                let len = dn_data[i + 6] as usize;
                if i + 7 + len <= dn_data.len() {
                    let value =
                        std::str::from_utf8(&dn_data[i + 7..i + 7 + len]).map_err(|error| {
                            crate::TlsError::ParseError {
                                message: format!("Invalid certificate request DN UTF-8: {error}"),
                            }
                        })?;
                    org = Some(value.to_string());
                }
            }
        }

        Ok((cn, org))
    }
}
