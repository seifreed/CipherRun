// Shared TLS handshake read helper used by vulnerability probes.
//
// Large certificate chains and bundled ServerHello/Certificate/ServerKeyExchange
// messages routinely span multiple TLS records (and multiple TCP reads). A
// single `stream.read(..)` call therefore captures only a prefix of the server
// handshake, which skews timing measurements and truncates certificate parsing.
//
// `read_until_server_hello_done` mirrors the pattern already used by
// `src/vulnerabilities/robot.rs` and extends it to any vulnerability probe that
// needs the full handshake in the buffer before sending the attack record.

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Return true once a ServerHelloDone record (handshake type 0x0e) is present
/// anywhere in the buffer.
pub(super) fn has_server_hello_done(buf: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 5 <= buf.len() {
        let content_type = buf[offset];
        let record_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > buf.len() {
            break;
        }
        if content_type == 0x16 {
            let hs_start = offset + 5;
            if hs_start < record_end && buf[hs_start] == 0x0e {
                return true;
            }
        }
        offset = record_end;
    }
    false
}

/// Read from `stream` into `buffer` until one of:
/// - A ServerHelloDone record is present in the accumulated bytes.
/// - The buffer fills up (prevents unbounded growth on adversarial servers).
/// - The per-read timeout elapses or the peer closes the connection.
///
/// Returns the number of bytes actually written into the buffer. Returns 0 if
/// the stream was closed or timed out before any data arrived.
pub(super) async fn read_until_server_hello_done(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    per_read_timeout: Duration,
) -> usize {
    let mut total = 0usize;
    loop {
        if total >= buffer.len() {
            break;
        }
        let n = match timeout(per_read_timeout, stream.read(&mut buffer[total..])).await {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if n == 0 {
            break;
        }
        total += n;
        if has_server_hello_done(&buffer[..total]) {
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TLS handshake record (content type 0x16) containing a single
    /// handshake message of `handshake_type` with a given body.
    fn handshake_record(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(4 + body.len());
        msg.push(handshake_type);
        let len = body.len();
        msg.push(((len >> 16) & 0xff) as u8);
        msg.push(((len >> 8) & 0xff) as u8);
        msg.push((len & 0xff) as u8);
        msg.extend_from_slice(body);

        let mut record = Vec::with_capacity(5 + msg.len());
        record.push(0x16);
        record.push(0x03);
        record.push(0x03);
        record.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&msg);
        record
    }

    #[test]
    fn detects_server_hello_done_across_records() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&handshake_record(0x02, &[0u8; 38])); // ServerHello
        buf.extend_from_slice(&handshake_record(0x0b, &[0u8; 64])); // Certificate
        buf.extend_from_slice(&handshake_record(0x0e, &[])); // ServerHelloDone
        assert!(has_server_hello_done(&buf));
    }

    #[test]
    fn returns_false_when_record_truncated() {
        let full = handshake_record(0x0e, &[]);
        // Slice short of the full record → not detected yet.
        assert!(!has_server_hello_done(&full[..6]));
    }

    #[test]
    fn returns_false_when_only_partial_records_present() {
        let incomplete = handshake_record(0x02, &[0u8; 38]);
        assert!(!has_server_hello_done(&incomplete));
    }
}
