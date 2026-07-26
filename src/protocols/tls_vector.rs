use crate::{Result, TlsError};

fn length_error(context: &str) -> TlsError {
    TlsError::Other(format!("{context} exceeds maximum length"))
}

pub(crate) fn u16_len(len: usize, context: &str) -> Result<u16> {
    u16::try_from(len).map_err(|_| length_error(context))
}

pub(crate) fn u16_byte_len(items: usize, context: &str) -> Result<u16> {
    let bytes = items.checked_mul(2).ok_or_else(|| length_error(context))?;
    u16_len(bytes, context)
}

pub(crate) fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
    let len = u32::try_from(len).map_err(|_| length_error(context))?;
    if len > 0x00ff_ffff {
        return Err(length_error(context));
    }
    let bytes = len.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
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
