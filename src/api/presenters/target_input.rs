use crate::api::models::{error::ApiError, request::ScanOptions};
use crate::application::ScanRequest;
use crate::constants::PORT_HTTPS;
use crate::security::{is_private_ip, validate_target};
use crate::utils::network::canonical_target;
use std::net::IpAddr;

const EMPTY_SCAN_OPTIONS_ERROR: &str = "Scan options must enable at least one scan phase";

fn validate_api_target(target: &str) -> Result<(String, u16), ApiError> {
    let (hostname, port) = validate_target(target, false)
        .map_err(|e| ApiError::BadRequest(format!("Invalid target: {}", e)))?;
    Ok((hostname, port.unwrap_or(PORT_HTTPS)))
}

fn validate_ip_override(ip_override: &str) -> Result<(), ApiError> {
    let ip: IpAddr = ip_override
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("Invalid IP override: {}", ip_override)))?;

    if is_private_ip(&ip) {
        return Err(ApiError::BadRequest(format!(
            "Invalid IP override: access to private IP addresses is not allowed: {}",
            ip
        )));
    }

    Ok(())
}

fn map_validation_error(error: crate::TlsError) -> ApiError {
    match error {
        crate::TlsError::InvalidInput { message } => ApiError::BadRequest(message),
        other => ApiError::BadRequest(other.to_string()),
    }
}

pub fn scan_request_from_target(target: &str) -> Result<ScanRequest, ApiError> {
    let (hostname, port) = validate_api_target(target)?;

    Ok(ScanRequest {
        target: Some(canonical_target(&hostname, port)),
        port: Some(port),
        ..Default::default()
    })
}

pub fn scan_request_from_target_and_options(
    target: &str,
    options: &ScanOptions,
) -> Result<ScanRequest, ApiError> {
    if !options.has_requested_scan_work() {
        return Err(ApiError::BadRequest(EMPTY_SCAN_OPTIONS_ERROR.to_string()));
    }

    let (hostname, port) = validate_api_target(target)?;

    if let Some(ip_override) = options.ip.as_deref() {
        validate_ip_override(ip_override)?;
    }

    let request = ScanRequest {
        target: Some(canonical_target(&hostname, port)),
        port: Some(port),
        scan: crate::application::scan_request::ScanRequestScan {
            scope: crate::application::scan_request::ScanRequestScope {
                all: options.full_scan,
                full: options.full_scan,
            },
            proto: crate::application::scan_request::ScanRequestProto {
                enabled: options.test_protocols
                    || options.full_scan
                    || options.starttls_protocol.is_some(),
                ..Default::default()
            },
            ciphers: crate::application::scan_request::ScanRequestCiphers {
                each_cipher: options.test_ciphers || options.full_scan,
                ..Default::default()
            },
            vulns: crate::application::scan_request::ScanRequestVulns {
                vulnerabilities: options.test_vulnerabilities || options.full_scan,
                ..Default::default()
            },
            certs: crate::application::scan_request::ScanRequestCerts {
                analyze_certificates: options.analyze_certificates || options.full_scan,
                ..Default::default()
            },
            prefs: crate::application::scan_request::ScanRequestPrefs {
                headers: options.test_http_headers || options.full_scan,
                ..Default::default()
            },
        },
        network: crate::application::scan_request::ScanRequestNetwork {
            ipv4_only: options.ipv4_only,
            ipv6_only: options.ipv6_only,
            ..Default::default()
        },
        connection: crate::application::scan_request::ScanRequestConnection {
            connect_timeout: Some(options.timeout_seconds),
            socket_timeout: Some(options.timeout_seconds),
            ..Default::default()
        },
        fingerprint: crate::application::scan_request::ScanRequestFingerprint {
            client_simulation: options.client_simulation || options.full_scan,
            ..Default::default()
        },
        starttls: crate::application::scan_request::ScanRequestStarttls {
            protocol: options.starttls_protocol.clone(),
            xmpphost: None,
            ..Default::default()
        },
        ip: options.ip.clone(),
        ..Default::default()
    };

    request.validate_common().map_err(map_validation_error)?;

    Ok(request)
}

pub fn full_scan_request_from_target(target: &str) -> Result<ScanRequest, ApiError> {
    scan_request_from_target_and_options(target, &ScanOptions::full())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::request::ScanOptions;

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
        let request = scan_request_from_target("2001:4860:4860::8888").expect("should parse");
        assert_eq!(
            request.target.as_deref(),
            Some("[2001:4860:4860::8888]:443")
        );
        assert_eq!(request.port, Some(443));
    }

    #[test]
    fn rejects_private_ip_target() {
        let err = scan_request_from_target("127.0.0.1").expect_err("private target should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn rejects_url_target() {
        let err =
            scan_request_from_target("https://example.com").expect_err("URL target should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn rejects_empty_scan_options_for_execution_requests() {
        let err = scan_request_from_target_and_options("example.com", &ScanOptions::default())
            .expect_err("empty options should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn maps_scan_options_into_application_request() {
        let options = ScanOptions {
            analyze_certificates: true,
            test_http_headers: true,
            timeout_seconds: 12,
            ip: Some("8.8.4.4".to_string()),
            ..Default::default()
        };

        let request = scan_request_from_target_and_options("example.com:8443", &options)
            .expect("request should build");

        assert_eq!(request.target.as_deref(), Some("example.com:8443"));
        assert_eq!(request.port, Some(8443));
        assert!(request.scan.certs.analyze_certificates);
        assert!(request.scan.prefs.headers);
        assert_eq!(request.connection.connect_timeout, Some(12));
        assert_eq!(request.connection.socket_timeout, Some(12));
        assert_eq!(request.ip.as_deref(), Some("8.8.4.4"));
    }

    #[test]
    fn starttls_only_request_enables_protocol_phase() {
        let options = ScanOptions {
            starttls_protocol: Some("smtp".to_string()),
            ..Default::default()
        };

        let request = scan_request_from_target_and_options("mail.example.com:25", &options)
            .expect("starttls-only request should build");

        assert!(request.scan.proto.enabled);
        assert_eq!(request.starttls.protocol.as_deref(), Some("smtp"));
    }

    #[test]
    fn rejects_conflicting_ip_family_options() {
        let options = ScanOptions {
            test_protocols: true,
            ipv4_only: true,
            ipv6_only: true,
            ..Default::default()
        };

        let err = scan_request_from_target_and_options("example.com", &options)
            .expect_err("conflicting IP family options should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn rejects_zero_timeout() {
        let options = ScanOptions {
            test_protocols: true,
            timeout_seconds: 0,
            ..Default::default()
        };

        let err = scan_request_from_target_and_options("example.com", &options)
            .expect_err("zero timeout should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn rejects_private_ip_override() {
        let options = ScanOptions {
            test_protocols: true,
            ip: Some("127.0.0.1".to_string()),
            ..Default::default()
        };

        let err = scan_request_from_target_and_options("example.com", &options)
            .expect_err("private IP override should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn rejects_malformed_ip_override() {
        let options = ScanOptions {
            test_protocols: true,
            ip: Some("not-an-ip".to_string()),
            ..Default::default()
        };

        let err = scan_request_from_target_and_options("example.com", &options)
            .expect_err("malformed IP override should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn builds_full_scan_request_from_target() {
        let request = full_scan_request_from_target("example.com").expect("request should build");

        assert_eq!(request.target.as_deref(), Some("example.com:443"));
        assert!(request.scan.scope.full);
        assert!(request.scan.proto.enabled);
        assert!(request.scan.ciphers.each_cipher);
        assert!(request.scan.vulns.vulnerabilities);
        assert!(request.scan.certs.analyze_certificates);
        assert!(request.scan.prefs.headers);
        assert!(request.fingerprint.client_simulation);
    }
}
