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

#[cfg(test)]
mod tests {
    use super::read_response_body_capped;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn local_response(response: &'static [u8]) -> reqwest::Response {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener address should exist");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("client should connect");
            stream.read_u8().await.expect("request should be readable");
            stream
                .write_all(response)
                .await
                .expect("response should be writable");
        });

        reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .expect("HTTP response should be received")
    }

    #[tokio::test]
    async fn accepts_body_at_limit_and_rejects_oversized_content_length() {
        let response = local_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
        )
        .await;
        assert_eq!(
            read_response_body_capped(response, 4, "test")
                .await
                .expect("body at limit should pass"),
            b"data"
        );

        let response = local_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
        )
        .await;
        let error = read_response_body_capped(response, 3, "test")
            .await
            .expect_err("oversized content length should be rejected");
        assert!(error.to_string().contains("response too large: 4 bytes"));
    }

    #[tokio::test]
    async fn rejects_chunked_body_after_it_exceeds_limit() {
        let response = local_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ndata\r\n0\r\n\r\n",
        )
        .await;

        let error = read_response_body_capped(response, 3, "test")
            .await
            .expect_err("chunked body over limit should be rejected");
        assert!(error.to_string().contains("response body too large"));
    }

    #[tokio::test]
    async fn reports_body_read_errors() {
        let response = local_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc",
        )
        .await;

        let error = read_response_body_capped(response, 20, "test")
            .await
            .expect_err("truncated body should fail");
        assert!(
            error
                .to_string()
                .contains("Failed to read test response body")
        );
    }
}
