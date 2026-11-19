use crate::{Result, TlsError};

fn parse_error(context: &str, reason: &str) -> TlsError {
    TlsError::ParseError {
        message: format!("{context} {reason}"),
    }
}

pub(crate) fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
    data.get(offset)
        .copied()
        .ok_or_else(|| parse_error(context, "truncated"))
}

pub(crate) fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| parse_error(context, "length overflow"))?;
    let bytes = data
        .get(offset..end)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .ok_or_else(|| parse_error(context, "truncated"))?;
    Ok(u16::from_be_bytes(bytes))
}

pub(crate) fn read_u24_at(data: &[u8], offset: usize, context: &str) -> Result<usize> {
    let end = offset
        .checked_add(3)
        .ok_or_else(|| parse_error(context, "length overflow"))?;
    let [high, mid, low] = data
        .get(offset..end)
        .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())
        .ok_or_else(|| parse_error(context, "truncated"))?;
    Ok(((high as usize) << 16) | ((mid as usize) << 8) | low as usize)
}

#[cfg(feature = "ct")]
pub(crate) fn read_u64_at(data: &[u8], offset: usize, context: &str) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| parse_error(context, "length overflow"))?;
    let bytes = data
        .get(offset..end)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .ok_or_else(|| parse_error(context, "truncated"))?;
    Ok(u64::from_be_bytes(bytes))
}

pub(crate) fn slice_range<'a>(
    data: &'a [u8],
    start: usize,
    len: usize,
    context: &str,
) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| parse_error(context, "length overflow"))?;
    data.get(start..end)
        .ok_or_else(|| parse_error(context, "truncated"))
}

#[cfg(test)]
mod reader_tests {
    use super::*;

    #[test]
    fn reads_integer_fields_and_rejects_truncated_or_overflowing_ranges() {
        let data = [0x12, 0x34, 0x56, 0x78];

        assert_eq!(read_u8_at(&data, 0, "value").unwrap(), 0x12);
        assert_eq!(read_u16_at(&data, 1, "value").unwrap(), 0x3456);
        assert_eq!(read_u24_at(&data, 1, "value").unwrap(), 0x345678);

        assert!(read_u8_at(&data, data.len(), "value").is_err());
        assert!(read_u16_at(&data, data.len() - 1, "value").is_err());
        assert!(read_u16_at(&data, usize::MAX, "value").is_err());
        assert!(read_u24_at(&data, data.len() - 2, "value").is_err());
        assert!(read_u24_at(&data, usize::MAX, "value").is_err());
    }

    #[test]
    fn slices_ranges_and_rejects_truncation_or_overflow() {
        let data = [0x12, 0x34, 0x56];

        assert_eq!(slice_range(&data, 1, 2, "value").unwrap(), &[0x34, 0x56]);
        assert!(slice_range(&data, 2, 2, "value").is_err());
        assert!(slice_range(&data, usize::MAX, 1, "value").is_err());
    }
}

#[cfg(all(test, feature = "ct"))]
mod tests {
    use super::*;

    #[test]
    fn read_u64_at_reads_big_endian_value() {
        let data = [0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

        assert_eq!(
            read_u64_at(&data, 1, "value").unwrap(),
            0x0123_4567_89ab_cdef
        );
        assert!(read_u64_at(&data, 2, "value").is_err());
        assert!(read_u64_at(&data, usize::MAX, "value").is_err());
    }
}
