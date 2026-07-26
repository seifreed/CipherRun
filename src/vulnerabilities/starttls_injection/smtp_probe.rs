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

    let (code, _greeting) = match timeout(
        Duration::from_secs(2),
        response::read_multiline_status(&mut reader, "SMTP", 100),
    )
    .await
    {
        Ok(Ok(result)) => result,
        _ => return Ok(StarttlsInjectionStatus::Inconclusive),
    };

    if code != 220 {
        return Ok(StarttlsInjectionStatus::NotVulnerable);
    }

    reader.get_mut().write_all(b"EHLO test.local\r\n").await?;
    match timeout(
        Duration::from_secs(2),
        response::read_multiline_status(&mut reader, "SMTP", 100),
    )
    .await
    {
        Ok(Ok(_)) => {}
        _ => return Ok(StarttlsInjectionStatus::Inconclusive),
    }

    reader
        .get_mut()
        .write_all(b"STARTTLS\r\nMAIL FROM:<injection@test.com>\r\n")
        .await?;

    let mut response = String::new();
    for _ in 0..8 {
        match timeout(
            Duration::from_secs(2),
            response::read_status_line(&mut reader, "SMTP"),
        )
        .await
        {
            Ok(Ok((_code, line))) => response.push_str(&line),
            Ok(Err(_)) if response.is_empty() => {
                return Ok(StarttlsInjectionStatus::Inconclusive);
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }

    if let Some(pos_220) = response_analysis::find_code_at_line_start(&response, "220")
        && let Some(pos_250) = response_analysis::find_code_at_line_start(&response, "250")
        && pos_250 > pos_220
    {
        Ok(StarttlsInjectionStatus::Vulnerable)
    } else {
        Ok(StarttlsInjectionStatus::NotVulnerable)
    }
}
