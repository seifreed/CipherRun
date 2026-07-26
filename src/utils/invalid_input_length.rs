use crate::{Result, TlsError};

fn length_error(context: &str) -> TlsError {
    TlsError::InvalidInput {
        message: format!("{context} exceeds maximum length"),
    }
}

pub(crate) fn u8_len(len: usize, context: &str) -> Result<u8> {
    u8::try_from(len).map_err(|_| length_error(context))
}

pub(crate) fn u16_len(len: usize, context: &str) -> Result<u16> {
    u16::try_from(len).map_err(|_| length_error(context))
}

pub(crate) fn u16_len_plus(len: usize, add: usize, context: &str) -> Result<u16> {
    let len = len.checked_add(add).ok_or_else(|| length_error(context))?;
    u16_len(len, context)
}

pub(crate) fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
    let len = u32::try_from(len).map_err(|_| length_error(context))?;
    if len > 0x00ff_ffff {
        return Err(length_error(context));
    }
    let bytes = len.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}
