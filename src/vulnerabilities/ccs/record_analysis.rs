use crate::constants::{CONTENT_TYPE_ALERT, CONTENT_TYPE_HANDSHAKE};

pub(super) fn alert_is_complete(buffer: &[u8], n: usize) -> bool {
    if n < 7 || n > buffer.len() || buffer.first() != Some(&CONTENT_TYPE_ALERT) {
        return false;
    }
    let alert_record_len = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
    alert_record_len == 2 && n == 5 + alert_record_len
}

pub(super) fn handshake_is_normal_continuation(record: &[u8], record_len: usize) -> bool {
    if record.first() != Some(&CONTENT_TYPE_HANDSHAKE) || record.len() != 5 + record_len {
        return false;
    }
    if record_len < 4 {
        return false;
    }
    matches!(
        record.get(5).copied(),
        Some(0x02 | 0x0B | 0x0C | 0x0D | 0x0E | 0x16)
    )
}
