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
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn read_u24_at(data: &[u8], offset: usize, context: &str) -> Result<usize> {
    let end = offset.checked_add(3).ok_or_else(|| parse_error(context))?;
    let bytes = data.get(offset..end).ok_or_else(|| parse_error(context))?;
    let [high, mid, low] = [bytes[0], bytes[1], bytes[2]];
    Ok(u32::from_be_bytes([0, high, mid, low]) as usize)
}

#[cfg(test)]
pub(super) fn write_u16_at(
    data: &mut [u8],
    offset: usize,
    value: u16,
    context: &str,
) -> Result<()> {
    let end = offset.checked_add(2).ok_or_else(|| parse_error(context))?;
    let bytes = data
        .get_mut(offset..end)
        .ok_or_else(|| parse_error(context))?;
    bytes.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(test)]
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
    let end = offset.checked_add(3).ok_or_else(|| parse_error(context))?;
    let bytes = data
        .get_mut(offset..end)
        .ok_or_else(|| parse_error(context))?;
    bytes.copy_from_slice(&value.to_be_bytes()[1..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian_values() {
        let data = [0x12, 0x34, 0xab, 0xcd, 0xef, 0, 0, 0];

        assert_eq!(read_u8_at(&data, 0, "u8").expect("u8 read"), 0x12);
        assert_eq!(read_u16_at(&data, 0, "u16").expect("u16 read"), 0x1234);
        assert_eq!(read_u24_at(&data, 2, "u24").expect("u24 read"), 0x00ab_cdef);
    }

    #[test]
    fn rejects_truncated_offsets() {
        let data = [0u8; 2];
        assert!(read_u16_at(&data, 1, "short read").is_err());
    }

    #[test]
    fn rejects_overflowing_offsets() {
        let data = [0u8; 3];

        assert!(read_u8_at(&[], 0, "u8").is_err());
        assert!(read_u16_at(&data, usize::MAX, "u16").is_err());
        assert!(read_u24_at(&data, 1, "u24").is_err());
        assert!(read_u24_at(&data, usize::MAX, "u24").is_err());

        let mut writable = [0u8; 3];
        assert!(write_u16_at(&mut writable, usize::MAX, 1, "u16").is_err());
        assert!(write_u24_at(&mut writable, usize::MAX, 1, "u24").is_err());
    }

    #[test]
    fn rejects_truncated_and_oversized_writes() {
        let mut short_u16 = [0u8; 1];
        assert!(write_u16_at(&mut short_u16, 0, 1, "u16").is_err());
        assert_eq!(short_u16, [0]);

        let mut short_u24 = [0u8; 2];
        assert!(write_u24_at(&mut short_u24, 0, 1, "u24").is_err());
        assert_eq!(short_u24, [0; 2]);

        let mut bytes = [0u8; 3];
        assert!(write_u24_at(&mut bytes, 0, 0x0100_0000, "u24").is_err());
        assert!(write_u24_at(&mut bytes, 0, usize::MAX, "u24").is_err());
        assert_eq!(bytes, [0; 3]);
    }
}
