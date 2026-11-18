pub(crate) fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

pub(crate) fn read_u24_at(data: &[u8], offset: usize) -> Option<usize> {
    let bytes = data.get(offset..offset.checked_add(3)?)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

pub(crate) fn slice_range(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    data.get(start..start.checked_add(len)?)
}

#[cfg(test)]
mod tests {
    use super::{read_u16_at, read_u24_at, slice_range};

    #[test]
    fn reads_big_endian_integers() {
        assert_eq!(read_u16_at(&[0x12, 0x34], 0), Some(0x1234));
        assert_eq!(read_u24_at(&[0x01, 0x02, 0x03], 0), Some(0x010203));
    }

    #[test]
    fn rejects_incomplete_and_overflowing_ranges() {
        assert_eq!(read_u16_at(&[0x12], 0), None);
        assert_eq!(read_u16_at(&[0x12, 0x34], usize::MAX), None);
        assert_eq!(read_u24_at(&[0x01, 0x02], 0), None);
        assert_eq!(read_u24_at(&[0x01, 0x02, 0x03], usize::MAX), None);
        assert_eq!(slice_range(&[0, 1, 2], 2, 2), None);
        assert_eq!(slice_range(&[0, 1, 2], usize::MAX, 1), None);
    }

    #[test]
    fn returns_requested_slice() {
        assert_eq!(slice_range(&[0, 1, 2, 3], 1, 2), Some(&[1, 2][..]));
    }
}
