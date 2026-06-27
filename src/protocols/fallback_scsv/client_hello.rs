use super::FallbackScsvTester;
use crate::Result;
use crate::constants::{COMPRESSION_NULL, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO};
use crate::error::TlsError;

impl FallbackScsvTester<'_> {
    pub(super) fn build_client_hello_with_scsv(
        &self,
        version: u16,
        include_scsv: bool,
    ) -> Result<Vec<u8>> {
        let mut hello = Vec::new();

        hello.push(CONTENT_TYPE_HANDSHAKE);
        hello.extend_from_slice(&version.to_be_bytes());

        let len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        hello.push(HANDSHAKE_TYPE_CLIENT_HELLO);

        let hs_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        hello.extend_from_slice(&version.to_be_bytes());

        for i in 0_u8..32 {
            hello.push(i.wrapping_mul(11));
        }

        hello.push(0x00);

        let cipher_count: u16 = if include_scsv { 3 } else { 2 };
        hello.extend_from_slice(&(cipher_count * 2).to_be_bytes());
        hello.extend_from_slice(&[0xc0, 0x2f, 0x00, 0x9c]);

        if include_scsv {
            hello.extend_from_slice(&[0x56, 0x00]);
        }

        hello.push(0x01);
        hello.push(COMPRESSION_NULL);

        let ext_start_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            hello.extend_from_slice(&[0x00, 0x00]);
            let hostname_len = Self::u16_len(hostname.len(), "SNI hostname")?;
            let sni_list_len = hostname_len
                .checked_add(3)
                .ok_or_else(|| TlsError::ParseError {
                    message: "SNI hostname length is too large".to_string(),
                })?;
            let sni_len = sni_list_len
                .checked_add(2)
                .ok_or_else(|| TlsError::ParseError {
                    message: "SNI extension length is too large".to_string(),
                })?;
            hello.extend_from_slice(&sni_len.to_be_bytes());

            hello.extend_from_slice(&sni_list_len.to_be_bytes());

            hello.push(0x00);
            hello.extend_from_slice(&hostname_len.to_be_bytes());
            hello.extend_from_slice(hostname.as_bytes());
        }

        let ext_len = hello.len() - ext_start_pos - 2;
        if let Some(len_bytes) = hello.get_mut(ext_start_pos..ext_start_pos + 2) {
            len_bytes.copy_from_slice(&Self::u16_len(ext_len, "Extensions")?.to_be_bytes());
        }

        let hs_len = hello.len() - hs_len_pos - 3;
        if let Some(len_bytes) = hello.get_mut(hs_len_pos..hs_len_pos + 3) {
            len_bytes.copy_from_slice(&Self::u24_len(hs_len, "Handshake")?);
        }

        let rec_len = hello.len() - len_pos - 2;
        if let Some(len_bytes) = hello.get_mut(len_pos..len_pos + 2) {
            len_bytes.copy_from_slice(&Self::u16_len(rec_len, "TLS record")?.to_be_bytes());
        }

        Ok(hello)
    }

    fn u16_len(len: usize, context: &str) -> Result<u16> {
        u16::try_from(len).map_err(|_| TlsError::ParseError {
            message: format!("{context} length is too large"),
        })
    }

    fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
        let len = u32::try_from(len).map_err(|_| TlsError::ParseError {
            message: format!("{context} length is too large"),
        })?;
        if len > 0x00FF_FFFF {
            return Err(TlsError::ParseError {
                message: format!("{context} length is too large"),
            });
        }
        let bytes = len.to_be_bytes();
        Ok([bytes[1], bytes[2], bytes[3]])
    }
}
