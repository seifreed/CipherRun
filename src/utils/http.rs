//! Bounded HTTP response-body reading.

use crate::Result;
use crate::error::TlsError;

/// Read an HTTP response body while enforcing a hard byte cap.
///
/// `response.bytes()`/`.text()` buffer the entire body with no limit, so an
/// endpoint whose URL the operator does not control — an OCSP responder or CRL
/// distribution point taken from the scanned certificate, or a MITM'd lookup —
/// can stream unbounded data and exhaust memory. A per-request timeout bounds
/// time, not size, so a fast attacker still wins.
///
/// The advertised `Content-Length` is rejected first, then the same cap is
/// enforced on the bytes actually read, because a chunked response carries no
/// `Content-Length` and could otherwise stream past the limit. Mirrors the
/// guard the CT-log client already applies to its own responses.
pub async fn read_response_body_capped(
    response: reqwest::Response,
    max_bytes: u64,
    what: &str,
) -> Result<Vec<u8>> {
    if let Some(len) = response.content_length()
        && len > max_bytes
    {
        return Err(TlsError::ParseError {
            message: format!("{what} response too large: {len} bytes (max {max_bytes})"),
        });
    }

    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| TlsError::ParseError {
        message: format!("Failed to read {what} response body: {e}"),
    })? {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > max_bytes {
            return Err(TlsError::ParseError {
                message: format!(
                    "{what} response body too large: >{} bytes (max {max_bytes})",
                    body.len()
                ),
            });
        }
    }

    Ok(body)
}
