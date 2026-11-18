use crate::{Result, TlsError};

fn length_error(context: &str) -> TlsError {
    TlsError::ParseError {
        message: format!("{context} length is too large"),
    }
}

pub(crate) fn u8_len(len: usize, context: &str) -> Result<u8> {
    u8::try_from(len).map_err(|_| length_error(context))
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
    if len > 0x00FF_FFFF {
        return Err(length_error(context));
    }
    let bytes = len.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::{u8_len, u16_byte_len, u16_len, u24_len};

    fn assert_length_error<T>(result: crate::Result<T>) {
        let error = result.err().expect("length should be rejected");
        assert!(error.to_string().contains("test length is too large"));
    }

    #[test]
    fn validates_integer_length_boundaries_and_overflow() {
        assert_eq!(u8_len(u8::MAX.into(), "test").unwrap(), u8::MAX);
        assert_length_error(u8_len(usize::from(u8::MAX) + 1, "test"));

        assert_eq!(u16_len(u16::MAX.into(), "test").unwrap(), u16::MAX);
        assert_length_error(u16_len(usize::from(u16::MAX) + 1, "test"));

        assert_eq!(
            u16_byte_len(usize::from(u16::MAX) / 2, "test").unwrap(),
            65_534
        );
        assert_length_error(u16_byte_len(usize::from(u16::MAX) / 2 + 1, "test"));
        assert_length_error(u16_byte_len(usize::MAX, "test"));

        assert_eq!(u24_len(0x00ff_ffff, "test").unwrap(), [0xff, 0xff, 0xff]);
        assert_length_error(u24_len(0x0100_0000, "test"));
        #[cfg(target_pointer_width = "64")]
        assert_length_error(u24_len(u32::MAX as usize + 1, "test"));
    }
}
