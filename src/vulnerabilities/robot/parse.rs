pub(super) fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)
        .and_then(|bytes| <&[u8; 2]>::try_from(bytes).ok())
        .map(|bytes| u16::from_be_bytes(*bytes))
}
