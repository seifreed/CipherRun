use crate::api::models::error::ApiError;
use crate::application::ScanRequest;
use crate::constants::PORT_HTTPS;
use crate::utils::network::{canonical_target, split_target_host_port};

pub fn scan_request_from_target(target: &str) -> Result<ScanRequest, ApiError> {
    if target.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Invalid target format. Expected hostname:port".to_string(),
        ));
    }

    let (hostname, port) = split_target_host_port(target).map_err(|_| {
        ApiError::BadRequest("Invalid target format. Expected hostname:port".to_string())
    })?;

    if hostname.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Invalid target format. Expected hostname:port".to_string(),
        ));
    }

    let port = port.unwrap_or(PORT_HTTPS);

    Ok(ScanRequest {
        target: Some(canonical_target(&hostname, port)),
        port: Some(port),
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

    #[test]
    fn parses_ipv6_target() {
        let request = scan_request_from_target("::1").expect("should parse");
        assert_eq!(request.target.as_deref(), Some("[::1]:443"));
        assert_eq!(request.port, Some(443));
    }
}
