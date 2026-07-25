use crate::Result;

fn parse_error(message: &str) -> crate::TlsError {
    crate::TlsError::ParseError {
        message: message.to_string(),
    }
}

pub(super) fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
    data.get(offset)
        .copied()
        .ok_or_else(|| parse_error(context))
}

pub(super) fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
    let end = offset.checked_add(2).ok_or_else(|| parse_error(context))?;
    let bytes = data.get(offset..end).ok_or_else(|| parse_error(context))?;
    let bytes: [u8; 2] = bytes.try_into().map_err(|_| parse_error(context))?;
    Ok(u16::from_be_bytes(bytes))
}

pub(super) fn read_u24_at(data: &[u8], offset: usize, context: &str) -> Result<usize> {
    let end = offset.checked_add(3).ok_or_else(|| parse_error(context))?;
    let bytes = data.get(offset..end).ok_or_else(|| parse_error(context))?;
    let bytes: [u8; 3] = bytes.try_into().map_err(|_| parse_error(context))?;
    let [high, mid, low] = bytes;
    Ok(u32::from_be_bytes([0, high, mid, low]) as usize)
}

pub(super) fn write_u16_at(
    data: &mut [u8],
    offset: usize,
    value: u16,
    context: &str,
) -> Result<()> {
    let bytes = value.to_be_bytes();
    slice_range_mut(data, offset, 2, context)?.copy_from_slice(&bytes);
    Ok(())
}

pub(super) fn u16_len(value: usize, context: &str) -> Result<u16> {
    u16::try_from(value).map_err(|_| parse_error(context))
}

pub(super) fn write_u24_at(
    data: &mut [u8],
    offset: usize,
    value: usize,
    context: &str,
) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| parse_error(context))?;
    if value > 0x00ff_ffff {
        return Err(parse_error(context));
    }
    let bytes = value.to_be_bytes();
    slice_range_mut(data, offset, 3, context)?.copy_from_slice(&bytes[1..]);
    Ok(())
}

fn slice_range_mut<'a>(
    data: &'a mut [u8],
    start: usize,
    len: usize,
    context: &str,
) -> Result<&'a mut [u8]> {
    let end = start.checked_add(len).ok_or_else(|| parse_error(context))?;
    data.get_mut(start..end).ok_or_else(|| parse_error(context))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_big_endian_values() {
        let mut data = [0u8; 8];

        write_u16_at(&mut data, 1, 0x1234, "u16").expect("u16 write");
        write_u24_at(&mut data, 3, 0x00ab_cdef, "u24").expect("u24 write");

        assert_eq!(read_u8_at(&data, 1, "u8").expect("u8 read"), 0x12);
        assert_eq!(read_u16_at(&data, 1, "u16").expect("u16 read"), 0x1234);
        assert_eq!(read_u24_at(&data, 3, "u24").expect("u24 read"), 0x00ab_cdef);
    }

    #[test]
    fn rejects_truncated_offsets() {
        let mut data = [0u8; 2];

        assert!(read_u16_at(&data, 1, "short read").is_err());
        assert!(write_u24_at(&mut data, 0, 1, "short write").is_err());
    }
}
