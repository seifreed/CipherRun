use crate::api::models::error::ApiError;
use crate::application::{HostPortInput, ScanRequest};

pub fn scan_request_from_target(target: &str) -> Result<ScanRequest, ApiError> {
    if target.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Invalid target format. Expected hostname:port".to_string(),
        ));
    }

    let parsed = HostPortInput::parse_with_default_port(target, 443);
    if parsed.hostname.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Invalid target format. Expected hostname:port".to_string(),
        ));
    }

    Ok(ScanRequest {
        target: Some(format!("{}:{}", parsed.hostname, parsed.port)),
        port: Some(parsed.port),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_target() {
        assert!(scan_request_from_target("").is_err());
    }

    #[test]
    fn parses_default_port() {
        let request = scan_request_from_target("example.com").expect("should parse");
        assert_eq!(request.target.as_deref(), Some("example.com:443"));
        assert_eq!(request.port, Some(443));
    }

    #[test]
    fn parses_explicit_port() {
        let request = scan_request_from_target("example.com:8443").expect("should parse");
        assert_eq!(request.target.as_deref(), Some("example.com:8443"));
        assert_eq!(request.port, Some(8443));
    }
}
