use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_RECORD_HEADER_SIZE};

pub(crate) fn total_len(header: &[u8; TLS_RECORD_HEADER_SIZE]) -> std::io::Result<Option<usize>> {
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = TLS_RECORD_HEADER_SIZE
        .checked_add(record_len)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLS record length overflow",
            )
        })?;
    if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
        return Ok(None);
    }
    Ok(Some(total_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_record() {
        let max_record_len = BUFFER_SIZE_MAX_WITH_OVERHEAD - TLS_RECORD_HEADER_SIZE;
        let allowed = max_record_len as u16;
        let rejected = (max_record_len + 1) as u16;

        let allowed_header = [0x16, 0x03, 0x03, (allowed >> 8) as u8, allowed as u8];
        assert_eq!(
            total_len(&allowed_header).expect("length should parse"),
            Some(BUFFER_SIZE_MAX_WITH_OVERHEAD)
        );

        let rejected_header = [0x16, 0x03, 0x03, (rejected >> 8) as u8, rejected as u8];
        assert_eq!(
            total_len(&rejected_header).expect("length should parse"),
            None
        );
    }
}
