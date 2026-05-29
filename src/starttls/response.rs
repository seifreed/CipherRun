// Shared STARTTLS response reading utilities
//
// These functions eliminate duplication across protocol-specific STARTTLS modules.
// All protocol negotiators should use these instead of implementing their own.

use crate::Result;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

/// Maximum line length for protocol responses (generous limit per RFC 5321).
const MAX_LINE_LENGTH: usize = 4096;

/// Read a single line from a buffered async reader.
///
/// Returns the raw line including any trailing CRLF.
/// Used by IMAP, POP3, Sieve, and as a building block for status-code protocols.
pub async fn read_line<S>(reader: &mut BufReader<&mut S>) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

/// Read a single line and parse a 3-digit status code from its prefix.
///
/// Returns `(status_code, full_line)`.
/// Fails if the line is shorter than 3 bytes, exceeds `MAX_LINE_LENGTH`,
/// or the prefix is not a valid u16.
///
/// Used by SMTP, FTP, LMTP, NNTP.
pub async fn read_status_line<S>(
    reader: &mut BufReader<&mut S>,
    protocol_name: &str,
) -> Result<(u16, String)>
where
    S: AsyncRead + Unpin,
{
    let line = read_line(reader).await?;

    if line.len() > MAX_LINE_LENGTH {
        return Err(crate::error::TlsError::ParseError {
            message: format!(
                "{} response line too long: {} bytes (max {})",
                protocol_name,
                line.len(),
                MAX_LINE_LENGTH
            ),
        });
    }

    if line.len() < 3 {
        return Err(crate::error::TlsError::ParseError {
            message: format!("Invalid {} response: too short", protocol_name),
        });
    }

    // Parse the 3-byte status code via bytes: slicing `line[0..3]` would panic if
    // a multi-byte UTF-8 character crosses byte index 3 (e.g. a hostile greeting
    // beginning with a non-ASCII char). Byte slicing is panic-free; non-digit or
    // non-UTF-8 prefixes fall through to the ParseError below.
    let code: u16 = std::str::from_utf8(&line.as_bytes()[..3])
        .ok()
        .and_then(|prefix| prefix.parse().ok())
        .ok_or_else(|| crate::error::TlsError::ParseError {
            message: format!("Invalid {} status code", protocol_name),
        })?;

    Ok((code, line))
}

/// Read a multi-line status response (FTP/SMTP style).
///
/// Continuation lines have format `NNN-text`, final line has `NNN text`.
/// Returns `(status_code, accumulated_response)`.
///
/// `max_lines` caps iterations to prevent infinite loops from malicious servers.
pub async fn read_multiline_status<S>(
    reader: &mut BufReader<&mut S>,
    protocol_name: &str,
    max_lines: usize,
) -> Result<(u16, String)>
where
    S: AsyncRead + Unpin,
{
    let mut full_response = String::new();
    let mut first_code = 0u16;

    for line_count in 0..max_lines {
        let (code, line) = read_status_line(reader, protocol_name).await?;

        if line_count == 0 {
            first_code = code;
        } else if code != first_code && line.as_bytes().get(3) == Some(&b' ') {
            // Final line of multi-line response may have a different code.
            // Per RFC 959, use the final line's code as the actual response.
            first_code = code;
        }

        full_response.push_str(&line);

        // Final line: "NNN " (space after code, not dash). Compare the 4th byte
        // directly so a multi-byte char at that position cannot panic the slice.
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }

    Ok((first_code, full_response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_read_line_returns_full_line() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            server
                .write_all(b"hello world\r\n")
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let line = read_line(&mut reader)
            .await
            .expect("read_line should succeed");
        assert_eq!(line, "hello world\r\n");
    }

    #[tokio::test]
    async fn test_read_status_line_valid() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            server
                .write_all(b"220 Ready\r\n")
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let (code, line) = read_status_line(&mut reader, "TEST")
            .await
            .expect("read_status_line should succeed");
        assert_eq!(code, 220);
        assert!(line.contains("Ready"));
    }

    #[tokio::test]
    async fn test_read_status_line_too_short() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            server
                .write_all(b"a\n")
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let err = read_status_line(&mut reader, "TEST").await.unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    #[tokio::test]
    async fn test_read_status_line_multibyte_prefix_does_not_panic() {
        // A line whose first bytes form a multi-byte char crossing index 3 must
        // yield a ParseError, not a panic from slicing on a non-char boundary.
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            server
                .write_all("a\u{1D400}xx\r\n".as_bytes())
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let err = read_status_line(&mut reader, "TEST").await.unwrap_err();
        assert!(format!("{err}").contains("Invalid TEST status code"));
    }

    #[tokio::test]
    async fn test_read_multiline_status_multibyte_separator_does_not_panic() {
        // A multi-byte char at byte index 3 (the code/separator position) must not
        // panic the final-line detection.
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // First line: multi-byte char at the separator position (continuation),
            // followed by a proper final line.
            server
                .write_all("250\u{1D400}cont\r\n250 done\r\n".as_bytes())
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let (code, _) = read_multiline_status(&mut reader, "TEST", 4)
            .await
            .expect("read_multiline_status should not panic");
        assert_eq!(code, 250);
    }

    #[tokio::test]
    async fn test_read_status_line_invalid_code() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            server
                .write_all(b"abc Invalid\r\n")
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let err = read_status_line(&mut reader, "TEST").await.unwrap_err();
        assert!(format!("{err}").contains("status code"));
    }

    #[tokio::test]
    async fn test_read_multiline_status() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"220-First line\r\n220 Ready\r\n")
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let (code, response) = read_multiline_status(&mut reader, "TEST", 100)
            .await
            .expect("read_multiline_status should succeed");
        assert_eq!(code, 220);
        assert!(response.contains("First line"));
        assert!(response.contains("220 Ready"));
    }

    #[tokio::test]
    async fn test_read_multiline_status_single_line() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            server
                .write_all(b"220 Ready\r\n")
                .await
                .expect("test should write data");
        });

        let mut reader = BufReader::new(&mut client);
        let (code, response) = read_multiline_status(&mut reader, "TEST", 100)
            .await
            .expect("read_multiline_status should succeed");
        assert_eq!(code, 220);
        assert!(response.contains("Ready"));
    }
}
