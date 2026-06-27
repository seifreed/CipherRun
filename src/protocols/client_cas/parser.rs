use super::{ClientCA, ClientCAsTester};

impl ClientCAsTester {
    fn read_u8_at(data: &[u8], offset: usize, context: &str) -> crate::Result<u8> {
        data.get(offset)
            .copied()
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })
    }

    fn read_u16_at(data: &[u8], offset: usize, context: &str) -> crate::Result<u16> {
        let end = offset
            .checked_add(2)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        let bytes = data
            .get(offset..end)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24_at(data: &[u8], offset: usize, context: &str) -> crate::Result<usize> {
        let end = offset
            .checked_add(3)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        let [high, mid, low] = data
            .get(offset..end)
            .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(((high as usize) << 16) | ((mid as usize) << 8) | low as usize)
    }

    fn slice_range<'a>(
        data: &'a [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> crate::Result<&'a [u8]> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        data.get(start..end)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })
    }

    pub(super) fn find_certificate_request(
        &self,
        data: &[u8],
    ) -> crate::Result<Option<Vec<ClientCA>>> {
        let mut cert_request = None;
        let mut pos = 0usize;
        let mut handshake_bytes = Vec::new();

        while let Some(header_end) = pos.checked_add(5).filter(|&end| end <= data.len()) {
            let record_len_offset =
                pos.checked_add(3)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "TLS record length offset overflow".to_string(),
                    })?;
            let record_len =
                Self::read_u16_at(data, record_len_offset, "TLS record length")? as usize;
            let record_end =
                header_end
                    .checked_add(record_len)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "TLS record length overflow".to_string(),
                    })?;
            if record_end > data.len() {
                return Err(crate::TlsError::ParseError {
                    message: "TLS record length exceeds available data".to_string(),
                });
            }

            if Self::read_u8_at(data, pos, "TLS record type")? != 0x16 {
                // Skip non-handshake records by reading the full record header + length
                pos = record_end;
                continue;
            }

            pos = header_end;

            handshake_bytes.extend_from_slice(Self::slice_range(
                data,
                pos,
                record_len,
                "TLS handshake record",
            )?);
            pos = record_end;
        }

        let mut msg_pos = 0usize;
        while let Some(msg_body_start) = msg_pos
            .checked_add(4)
            .filter(|&end| end <= handshake_bytes.len())
        {
            let msg_type = Self::read_u8_at(&handshake_bytes, msg_pos, "Handshake message type")?;
            let msg_len_offset =
                msg_pos
                    .checked_add(1)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Handshake message length offset overflow".to_string(),
                    })?;
            let msg_len =
                Self::read_u24_at(&handshake_bytes, msg_len_offset, "Handshake message length")?;
            let msg_end =
                msg_body_start
                    .checked_add(msg_len)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Handshake message length overflow".to_string(),
                    })?;

            if msg_end > handshake_bytes.len() {
                return Err(crate::TlsError::ParseError {
                    message: "Handshake message length exceeds available data".to_string(),
                });
            }

            if msg_type == 13 {
                cert_request = Some(self.parse_ca_list(Self::slice_range(
                    &handshake_bytes,
                    msg_pos,
                    4 + msg_len,
                    "CertificateRequest message",
                )?)?);
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
        let cert_types_len =
            Self::read_u8_at(data, pos, "CertificateRequest certificate types")? as usize;
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
        let sig_algs_len =
            Self::read_u16_at(data, pos, "CertificateRequest signature algorithms length")?
                as usize;
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

        let ca_list_len =
            Self::read_u16_at(data, pos, "CertificateRequest CA list length")? as usize;
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
        let ca_data = Self::slice_range(data, pos, ca_list_len, "CertificateRequest CA list")?;
        let mut ca_pos = 0usize;

        while let Some(dn_len_end) = ca_pos.checked_add(2).filter(|&end| end <= ca_data.len()) {
            let dn_len =
                Self::read_u16_at(ca_data, ca_pos, "CertificateRequest CA DN length")? as usize;
            ca_pos = dn_len_end;

            let dn_end = ca_pos
                .checked_add(dn_len)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "CertificateRequest CA distinguished name length overflow".to_string(),
                })?;
            if dn_end > ca_data.len() {
                return Err(crate::TlsError::ParseError {
                    message: "CertificateRequest CA distinguished name length exceeds list"
                        .to_string(),
                });
            }

            let dn_data = Self::slice_range(ca_data, ca_pos, dn_len, "CertificateRequest CA DN")?;
            let dn_hex = hex::encode(dn_data);
            let (cn, org) = self.extract_dn_fields(dn_data)?;

            cas.push(ClientCA {
                distinguished_name: dn_hex,
                common_name: cn,
                organization: org,
            });

            ca_pos = dn_end;
        }

        if ca_pos != ca_data.len() {
            return Err(crate::TlsError::ParseError {
                message: "CertificateRequest CA list contains trailing bytes".to_string(),
            });
        }

        Ok(cas)
    }

    pub(super) fn extract_dn_fields(
        &self,
        dn_data: &[u8],
    ) -> crate::Result<(Option<String>, Option<String>)> {
        let mut cn = None;
        let mut org = None;

        for i in 0..dn_data.len().saturating_sub(6) {
            let Some(oid_mid) = i.checked_add(3) else {
                break;
            };
            let Some(oid_end) = i.checked_add(6) else {
                break;
            };
            let oid_prefix = dn_data.get(i..oid_mid);
            let oid_type = dn_data.get(oid_mid..oid_end);

            if dn_data
                .get(i..)
                .is_some_and(|remaining| remaining.len() >= 9)
                && oid_prefix == Some(&[0x06, 0x03, 0x55])
                && (oid_type == Some(&[0x04, 0x03, 0x0c]) || oid_type == Some(&[0x04, 0x03, 0x13]))
            {
                let len = Self::read_u8_at(dn_data, oid_end, "CertificateRequest DN value length")?
                    as usize;
                let Some(value_start) = oid_end.checked_add(1) else {
                    break;
                };
                let value_end = value_start.checked_add(len);
                if let Some(value_bytes) = value_end.and_then(|end| dn_data.get(value_start..end)) {
                    let value = std::str::from_utf8(value_bytes).map_err(|error| {
                        crate::TlsError::ParseError {
                            message: format!("Invalid certificate request DN UTF-8: {error}"),
                        }
                    })?;
                    cn = Some(value.to_string());
                }
            }

            if dn_data
                .get(i..)
                .is_some_and(|remaining| remaining.len() >= 9)
                && oid_prefix == Some(&[0x06, 0x03, 0x55])
                && (oid_type == Some(&[0x04, 0x0a, 0x0c]) || oid_type == Some(&[0x04, 0x0a, 0x13]))
            {
                let len = Self::read_u8_at(dn_data, oid_end, "CertificateRequest DN value length")?
                    as usize;
                let Some(value_start) = oid_end.checked_add(1) else {
                    break;
                };
                let value_end = value_start.checked_add(len);
                if let Some(value_bytes) = value_end.and_then(|end| dn_data.get(value_start..end)) {
                    let value = std::str::from_utf8(value_bytes).map_err(|error| {
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
