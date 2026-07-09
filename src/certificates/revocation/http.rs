use crate::security::input_validation::{looks_like_dotted_ip_literal, looks_like_obfuscated_ip};
use crate::security::{is_private_ip, validate_hostname};
use crate::{Result, TlsError};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use url::Url;

#[derive(Debug)]
pub(crate) struct ValidatedRevocationHttp {
    pub(crate) url: Url,
    pub(crate) client: reqwest::Client,
}

pub(crate) async fn validate_revocation_http_url(
    uri: &str,
    timeout: Duration,
) -> Result<ValidatedRevocationHttp> {
    if raw_revocation_host(uri).is_some_and(looks_like_obfuscated_ip) {
        return Err(TlsError::InvalidInput {
            message: "Revocation URL must not use obfuscated IP notation".to_string(),
        });
    }
    if raw_revocation_host(uri).is_some_and(looks_like_dotted_ip_literal) {
        return Err(TlsError::InvalidInput {
            message: "Revocation URL must not use dotted IP literals".to_string(),
        });
    }

    let url = Url::parse(uri).map_err(|error| TlsError::InvalidInput {
        message: format!("Invalid revocation URL: {error}"),
    })?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(TlsError::InvalidInput {
            message: "Revocation URL must use http or https".to_string(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TlsError::InvalidInput {
            message: "Revocation URL must not contain credentials".to_string(),
        });
    }

    let host = url.host_str().ok_or_else(|| TlsError::InvalidInput {
        message: "Revocation URL must include a host".to_string(),
    })?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) {
            return Err(TlsError::InvalidInput {
                message: format!("Revocation URL resolves to private/internal IP {ip}"),
            });
        }
    } else {
        validate_hostname(host).map_err(|error| TlsError::InvalidInput {
            message: format!("Invalid revocation URL host: {error}"),
        })?;
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| TlsError::InvalidInput {
            message: "Revocation URL must include a valid port".to_string(),
        })?;
    let addrs: Vec<_> = lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(TlsError::InvalidInput {
            message: "Revocation URL host did not resolve".to_string(),
        });
    }
    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            return Err(TlsError::InvalidInput {
                message: format!(
                    "Revocation URL resolves to private/internal IP {}",
                    addr.ip()
                ),
            });
        }
    }

    let mut client_builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    for addr in ordered_addrs(&addrs) {
        client_builder = client_builder.resolve(host, addr);
    }

    Ok(ValidatedRevocationHttp {
        url,
        client: client_builder.build()?,
    })
}

fn raw_revocation_host(uri: &str) -> Option<&str> {
    let authority = uri.split_once("://")?.1;
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let host = authority.rsplit_once('@').map(|(_, host)| host).unwrap_or(authority);

    if let Some(host) = host.strip_prefix('[') {
        host.split_once(']').map(|(host, _)| host)
    } else {
        Some(host.split_once(':').map_or(host, |(hostname, _)| hostname))
    }
}

fn ordered_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut addrs = addrs.to_vec();
    addrs.sort_by_key(|addr| addr.ip().is_ipv6());
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_validate_revocation_http_url_rejects_private_ip() {
        let err = validate_revocation_http_url("http://127.0.0.1/crl", Duration::from_secs(1))
            .await
            .expect_err("private revocation URL should be rejected");

        assert!(err.to_string().contains("private/internal IP"));
    }

    #[tokio::test]
    async fn test_validate_revocation_http_url_rejects_obfuscated_ip() {
        let err = validate_revocation_http_url("http://127.1/crl", Duration::from_secs(1))
            .await
            .expect_err("obfuscated revocation URL should be rejected");

        assert!(err.to_string().contains("obfuscated IP"));
    }

    #[tokio::test]
    async fn test_validate_revocation_http_url_rejects_dotted_ip() {
        let err = validate_revocation_http_url("http://127.0.0.1./crl", Duration::from_secs(1))
            .await
            .expect_err("dotted revocation URL should be rejected");

        assert!(err.to_string().contains("dotted IP"));
    }

    #[tokio::test]
    async fn test_validate_revocation_http_url_rejects_credentials() {
        let err = validate_revocation_http_url(
            "https://user:pass@example.com/ocsp",
            Duration::from_secs(1),
        )
        .await
        .expect_err("credentialed revocation URL should be rejected");

        assert!(err.to_string().contains("credentials"));
    }

    #[test]
    fn test_ordered_addrs_prefers_ipv4() {
        let addrs = vec![
            "[::1]:443".parse::<SocketAddr>().expect("ipv6 should parse"),
            "127.0.0.1:443".parse::<SocketAddr>().expect("ipv4 should parse"),
        ];

        let ordered = ordered_addrs(&addrs);

        assert!(!ordered[0].ip().is_ipv6());
        assert!(ordered[1].ip().is_ipv6());
    }
}
