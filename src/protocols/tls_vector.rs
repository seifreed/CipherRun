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
    let data = sni_extension_data(server_name)?;
    let ext_len = u16_len(data.len(), "SNI extension")?;

    let mut sni = Vec::with_capacity(usize::from(ext_len) + 4);
    sni.extend_from_slice(&[0x00, 0x00]);
    sni.extend_from_slice(&ext_len.to_be_bytes());
    sni.extend_from_slice(&data);
    Ok(sni)
}

pub(crate) fn sni_extension_data(server_name: &[u8]) -> Result<Vec<u8>> {
    let name_len = u16_len(server_name.len(), "SNI server name")?;
    let list_len = name_len
        .checked_add(3)
        .ok_or_else(|| crate::TlsError::InvalidInput {
            message: "SNI server name list exceeds maximum length".to_string(),
        })?;
    let mut sni = Vec::with_capacity(usize::from(list_len) + 2);
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

        #[cfg(target_pointer_width = "64")]
        assert!(
            crate::utils::invalid_input_length::u24_len(u32::MAX as usize + 1, "handshake")
                .is_err()
        );
    }

    #[test]
    fn u16_byte_len_rejects_multiplication_overflow() {
        let err = u16_byte_len(usize::MAX, "items").expect_err("length must be rejected");
        assert!(err.to_string().contains("items exceeds maximum length"));
    }

    #[test]
    fn sni_rejects_lengths_that_overflow_nested_vectors() {
        let name_list_overflow = vec![b'a'; 65_533];
        let err = sni_extension_data(&name_list_overflow)
            .expect_err("SNI name list length must fit in 16 bits");
        assert!(
            err.to_string()
                .contains("SNI server name list exceeds maximum length")
        );

        let err = sni_extension(&name_list_overflow)
            .expect_err("extension should propagate SNI name-list errors");
        assert!(
            err.to_string()
                .contains("SNI server name list exceeds maximum length")
        );

        let extension_overflow = vec![b'a'; 65_532];
        let err = sni_extension(&extension_overflow)
            .expect_err("encoded SNI extension length must fit in 16 bits");
        assert!(
            err.to_string()
                .contains("SNI extension exceeds maximum length")
        );
    }
}
