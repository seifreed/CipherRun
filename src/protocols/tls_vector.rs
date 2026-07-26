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
