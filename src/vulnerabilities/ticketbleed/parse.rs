pub(super) fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

pub(super) fn read_u24_at(data: &[u8], offset: usize) -> Option<usize> {
    data.get(offset..offset.checked_add(3)?)
        .and_then(|bytes| <&[u8; 3]>::try_from(bytes).ok())
        .map(|bytes| {
            let [high, mid, low] = *bytes;
            u32::from_be_bytes([0, high, mid, low]) as usize
        })
}
