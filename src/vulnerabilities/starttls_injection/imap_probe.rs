use super::response_analysis;
use super::result_analysis::StarttlsInjectionStatus;
use crate::Result;
use crate::starttls::response;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

pub(super) async fn test_command_injection(
    mut stream: TcpStream,
) -> Result<StarttlsInjectionStatus> {
    let mut reader = BufReader::new(&mut stream);
    let response = match timeout(Duration::from_secs(2), response::read_line(&mut reader)).await {
        Ok(Ok(line)) if !line.is_empty() => line,
        _ => return Ok(StarttlsInjectionStatus::Inconclusive),
    };

    if !response.starts_with("* OK") {
        return Ok(StarttlsInjectionStatus::NotVulnerable);
    }

    reader.get_mut().write_all(b"a001 CAPABILITY\r\n").await?;
    let response = match timeout(Duration::from_secs(2), response::read_line(&mut reader)).await {
        Ok(Ok(line)) if !line.is_empty() => line,
        _ => return Ok(StarttlsInjectionStatus::Inconclusive),
    };

    if !response_analysis::has_ascii_token(&response, "STARTTLS") {
        return Ok(StarttlsInjectionStatus::NotVulnerable);
    }

    reader
        .get_mut()
        .write_all(b"a002 STARTTLS\r\na003 LOGIN test test\r\n")
        .await?;

    let mut response = String::new();
    for _ in 0..4 {
        let line = match timeout(Duration::from_secs(2), response::read_line(&mut reader)).await {
            Ok(Ok(line)) if !line.is_empty() => line,
            Ok(Err(_)) | Err(_) if response.is_empty() => {
                return Ok(StarttlsInjectionStatus::Inconclusive);
            }
            Ok(Err(_)) | Err(_) => break,
            _ => break,
        };
        response.push_str(&line);
    }

    if response_analysis::has_code_at_line_start(&response, "a003") {
        Ok(StarttlsInjectionStatus::Vulnerable)
    } else {
        Ok(StarttlsInjectionStatus::NotVulnerable)
    }
}
