use crate::Result;
use crate::utils::invalid_input_length as length;

pub(crate) fn u8_len(len: usize, context: &str) -> Result<u8> {
    length::u8_len(len, context)
}

pub(crate) fn u16_len(len: usize, context: &str) -> Result<u16> {
    length::u16_len(len, context)
}

pub(crate) fn u16_byte_len(items: usize, context: &str) -> Result<u16> {
    length::u16_len_plus(items, items, context)
}

pub(crate) fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
    length::u24_len(len, context)
}

pub(crate) fn sni_extension(server_name: &[u8]) -> Result<Vec<u8>> {
    let name_len = u16_len(server_name.len(), "SNI server name")?;
    let list_len = name_len
        .checked_add(3)
        .ok_or_else(|| crate::TlsError::InvalidInput {
            message: "SNI server name list exceeds maximum length".to_string(),
        })?;
    let ext_len = list_len
        .checked_add(2)
        .ok_or_else(|| crate::TlsError::InvalidInput {
            message: "SNI extension exceeds maximum length".to_string(),
        })?;

    let mut sni = Vec::with_capacity(usize::from(ext_len) + 4);
    sni.extend_from_slice(&[0x00, 0x00]);
    sni.extend_from_slice(&ext_len.to_be_bytes());
    sni.extend_from_slice(&list_len.to_be_bytes());
    sni.push(0x00);
    sni.extend_from_slice(&name_len.to_be_bytes());
    sni.extend_from_slice(server_name);
    Ok(sni)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u24_len_rejects_values_above_24_bits() {
        let err = u24_len(0x0100_0000, "handshake").expect_err("length must be rejected");
        assert!(err.to_string().contains("handshake exceeds maximum length"));
    }

    #[test]
    fn u16_byte_len_rejects_multiplication_overflow() {
        let err = u16_byte_len(usize::MAX, "items").expect_err("length must be rejected");
        assert!(err.to_string().contains("items exceeds maximum length"));
    }
}
