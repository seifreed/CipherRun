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

    let code: u16 = line[0..3]
        .parse()
        .map_err(|_| crate::error::TlsError::ParseError {
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
        } else if code != first_code && line.len() >= 4 && &line[3..4] == " " {
            // Final line of multi-line response may have a different code.
            // Per RFC 959, use the final line's code as the actual response.
            first_code = code;
        }

        full_response.push_str(&line);

        // Final line: "NNN " (space after code, not dash)
        if line.len() >= 4 && &line[3..4] == " " {
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
