use super::{ClientCA, ClientCAsTester};

impl ClientCAsTester {
    pub(super) fn find_certificate_request(&self, data: &[u8]) -> Option<Vec<ClientCA>> {
        let mut cert_request = None;
        let mut pos = 0;
        let mut handshake_bytes = Vec::new();

        while pos + 5 <= data.len() {
            if data[pos] != 0x16 {
                // Skip non-handshake records by reading the full record header + length
                if pos + 5 <= data.len() {
                    let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                    pos += 5 + record_len;
                } else {
                    break;
                }
                continue;
            }

            let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            pos += 5;

            if pos + record_len > data.len() {
                break;
            }

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
                break;
            }

            if msg_type == 13 {
                cert_request = Some(
                    self.parse_ca_list(&handshake_bytes[msg_pos..msg_end])
                        .unwrap_or_default(),
                );
                break;
            }

            msg_pos = msg_end;
        }

        cert_request
    }

    #[cfg(test)]
    pub(super) fn parse_certificate_request(&self, data: &[u8]) -> Vec<ClientCA> {
        self.find_certificate_request(data).unwrap_or_default()
    }

    pub(super) fn parse_ca_list(&self, data: &[u8]) -> Option<Vec<ClientCA>> {
        if data.len() < 10 {
            return None;
        }

        let mut pos = 4;

        if pos >= data.len() {
            return None;
        }
        let cert_types_len = data[pos] as usize;
        pos += 1 + cert_types_len;

        if pos + 2 > data.len() {
            return None;
        }
        let sig_algs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + sig_algs_len;

        if pos + 2 > data.len() {
            return None;
        }

        let ca_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + ca_list_len > data.len() {
            return None;
        }

        let mut cas = Vec::new();
        let ca_data = &data[pos..pos + ca_list_len];
        let mut ca_pos = 0;

        while ca_pos + 2 <= ca_data.len() {
            let dn_len = u16::from_be_bytes([ca_data[ca_pos], ca_data[ca_pos + 1]]) as usize;
            ca_pos += 2;

            if ca_pos + dn_len > ca_data.len() {
                break;
            }

            let dn_data = &ca_data[ca_pos..ca_pos + dn_len];
            let dn_hex = hex::encode(dn_data);
            let (cn, org) = self.extract_dn_fields(dn_data);

            cas.push(ClientCA {
                distinguished_name: dn_hex,
                common_name: cn,
                organization: org,
            });

            ca_pos += dn_len;
        }

        Some(cas)
    }

    pub(super) fn extract_dn_fields(&self, dn_data: &[u8]) -> (Option<String>, Option<String>) {
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
                if i + 7 + len <= dn_data.len()
                    && let Ok(value) = std::str::from_utf8(&dn_data[i + 7..i + 7 + len])
                {
                    cn = Some(value.to_string());
                }
            }

            if dn_data[i..].len() >= 9
                && dn_data[i..i + 3] == [0x06, 0x03, 0x55]
                && (dn_data[i + 3..i + 6] == [0x04, 0x0a, 0x0c]
                    || dn_data[i + 3..i + 6] == [0x04, 0x0a, 0x13])
            {
                let len = dn_data[i + 6] as usize;
                if i + 7 + len <= dn_data.len()
                    && let Ok(value) = std::str::from_utf8(&dn_data[i + 7..i + 7 + len])
                {
                    org = Some(value.to_string());
                }
            }
        }

        (cn, org)
    }
}
