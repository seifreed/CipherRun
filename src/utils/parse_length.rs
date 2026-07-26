use crate::{Result, TlsError};

fn length_error(context: &str) -> TlsError {
    TlsError::ParseError {
        message: format!("{context} length is too large"),
    }
}

pub(crate) fn u16_len(len: usize, context: &str) -> Result<u16> {
    u16::try_from(len).map_err(|_| length_error(context))
}

pub(crate) fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
    let len = u32::try_from(len).map_err(|_| length_error(context))?;
    if len > 0x00FF_FFFF {
        return Err(length_error(context));
    }
    let bytes = len.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}
