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

    if !response.starts_with("+OK") {
        return Ok(StarttlsInjectionStatus::NotVulnerable);
    }

    reader.get_mut().write_all(b"CAPA\r\n").await?;
    let mut response = String::new();
    for _ in 0..8 {
        let line = match timeout(Duration::from_secs(2), response::read_line(&mut reader)).await {
            Ok(Ok(line)) if !line.is_empty() => line,
            Ok(Err(_)) | Err(_) if response.is_empty() => {
                return Ok(StarttlsInjectionStatus::Inconclusive);
            }
            Ok(Err(_)) | Err(_) => break,
            _ => break,
        };
        response.push_str(&line);
        if line.trim() == "." {
            break;
        }
    }

    if !response_analysis::has_ascii_token(&response, "STLS") {
        return Ok(StarttlsInjectionStatus::NotVulnerable);
    }

    reader
        .get_mut()
        .write_all(b"STLS\r\nUSER injection\r\n")
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

    if response_analysis::has_multiple_pop3_ok_lines(&response) {
        Ok(StarttlsInjectionStatus::Vulnerable)
    } else {
        Ok(StarttlsInjectionStatus::NotVulnerable)
    }
}
