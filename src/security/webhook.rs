use crate::Result;
use crate::error::TlsError;
use crate::security::input_validation::{is_private_ip, looks_like_obfuscated_ip};
use crate::security::url::raw_url_host;
use crate::security::validate_hostname;
use crate::utils::network::canonical_target;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct ValidatedWebhook {
    pub(crate) host: String,
    pub(crate) resolved_addrs: Vec<SocketAddr>,
}

pub(crate) fn webhook_http_client(validated: &ValidatedWebhook) -> Result<reqwest::Client> {
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none());
    for addr in ordered_resolved_addrs(&validated.resolved_addrs) {
        client_builder = client_builder.resolve(&validated.host, addr);
    }
    Ok(client_builder.build()?)
}

pub(crate) async fn validate_webhook_url(webhook_url: &str) -> Result<ValidatedWebhook> {
    if raw_url_host(webhook_url).is_some_and(looks_like_obfuscated_ip) {
        return Err(TlsError::InvalidInput {
            message: "Webhook URL uses obfuscated IP notation".to_string(),
        });
    }

    let url: url::Url = webhook_url.parse().map_err(|e| TlsError::InvalidInput {
        message: format!("Invalid webhook URL: {e}"),
    })?;

    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(TlsError::InvalidInput {
                message: format!("Webhook URL scheme '{scheme}' not allowed (only http/https)"),
            });
        }
    }
    if matches!(url.port(), Some(0)) {
        return Err(TlsError::InvalidInput {
            message: "Webhook URL port must be between 1 and 65535".to_string(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TlsError::InvalidInput {
            message: "Webhook URL must not contain credentials".to_string(),
        });
    }

    let host = url
        .host_str()
        .ok_or_else(|| TlsError::InvalidInput {
            message: "Webhook URL has no host".to_string(),
        })?
        .to_string();
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&host)
        .to_string();
    let host_ip = host.parse::<std::net::IpAddr>().ok();
    if host_ip.is_none() {
        validate_hostname(&host).map_err(|error| TlsError::InvalidInput {
            message: format!("Invalid webhook URL: {error}"),
        })?;
    }
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    let allow_loopback_only =
        normalized_host == "localhost" || host_ip.is_some_and(|ip| ip.is_loopback());

    if normalized_host == "localhost"
        || normalized_host.ends_with(".local")
        || normalized_host.ends_with(".internal")
    {
        return Err(TlsError::InvalidInput {
            message: format!("Webhook URL points to private/local host: {host}"),
        });
    }
    if looks_like_obfuscated_ip(&host) {
        return Err(TlsError::InvalidInput {
            message: format!("Webhook URL uses obfuscated IP notation: {host}"),
        });
    }

    if let Some(ip) = host_ip
        && is_private_ip(&ip)
        && !ip.is_loopback()
    {
        return Err(TlsError::InvalidInput {
            message: format!("Webhook URL uses private/internal IP literal {ip} (SSRF blocked)"),
        });
    }

    let lookup_target = webhook_lookup_target(&host, url.port_or_known_default().unwrap_or(80));
    let resolved_addrs: Vec<_> = tokio::net::lookup_host(lookup_target)
        .await
        .map_err(|e| TlsError::InvalidInput {
            message: format!(
                "Webhook DNS resolution failed for {host}: {e} (SSRF protection requires successful DNS resolution)"
            ),
        })?
        .collect();

    if resolved_addrs.is_empty() {
        return Err(TlsError::InvalidInput {
            message: format!(
                "Webhook DNS resolution returned no addresses for {host} (SSRF blocked)"
            ),
        });
    }

    for addr in &resolved_addrs {
        if allow_loopback_only {
            if !addr.ip().is_loopback() {
                return Err(TlsError::InvalidInput {
                    message: "Webhook URL must resolve only to loopback addresses".to_string(),
                });
            }
            continue;
        }

        if is_private_ip(&addr.ip()) {
            return Err(TlsError::InvalidInput {
                message: format!(
                    "Webhook URL resolves to private/internal IP {} (SSRF blocked)",
                    addr.ip()
                ),
            });
        }
    }

    Ok(ValidatedWebhook {
        host,
        resolved_addrs: ordered_resolved_addrs(&resolved_addrs),
    })
}

fn webhook_lookup_target(host: &str, port: u16) -> String {
    canonical_target(host, port)
}

fn ordered_resolved_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut addrs = addrs.to_vec();
    addrs.sort_by_key(|addr| addr.ip().is_ipv6());
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_lookup_target_brackets_ipv6() {
        assert_eq!(
            webhook_lookup_target("2001:db8::1", 443),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn test_webhook_lookup_target_strips_existing_brackets() {
        assert_eq!(
            webhook_lookup_target("[2001:db8::1]", 443),
            "[2001:db8::1]:443"
        );
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_private_hostnames() {
        let err = validate_webhook_url("https://localhost/callback")
            .await
            .expect_err("localhost should fail");
        assert!(err.to_string().contains("private/local host"));
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_obfuscated_ip_notation() {
        let err = validate_webhook_url("https://127.1/callback")
            .await
            .expect_err("obfuscated IP should fail");
        assert!(err.to_string().contains("obfuscated IP notation"));
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_dotted_ip_literal() {
        let err = validate_webhook_url("https://10.0.0.1./callback")
            .await
            .expect_err("dotted IP should fail");
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_trailing_dot_localhost() {
        let err = validate_webhook_url("https://localhost./callback")
            .await
            .expect_err("localhost with trailing dot should fail");
        assert!(err.to_string().contains("private/local host"));
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_invalid_scheme() {
        let err = validate_webhook_url("ftp://example.com/callback")
            .await
            .expect_err("invalid scheme should fail");
        assert!(err.to_string().contains("only http/https"));
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_zero_port() {
        let err = validate_webhook_url("https://example.com:0/callback")
            .await
            .expect_err("port zero should fail");
        assert!(err.to_string().contains("port must be between"));
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_credentials() {
        let err = validate_webhook_url("https://user:pass@example.com/callback")
            .await
            .expect_err("credentials should fail");
        assert!(err.to_string().contains("credentials"));
    }

    #[tokio::test]
    async fn test_validate_webhook_url_allows_loopback_ipv6_literal() {
        assert!(validate_webhook_url("https://[::1]/callback").await.is_ok());
    }

    #[tokio::test]
    async fn test_webhook_client_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("client should connect");
            let mut request = [0_u8; 1024];
            let _ = socket
                .read(&mut request)
                .await
                .expect("request should read");
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/private\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .expect("redirect response should write");
        });

        let validated = ValidatedWebhook {
            host: "example.test".to_string(),
            resolved_addrs: vec![addr],
        };
        let client = webhook_http_client(&validated).expect("webhook client should build");
        let response = client
            .post(format!("http://example.test:{}/callback", addr.port()))
            .send()
            .await
            .expect("redirect response should be returned");

        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.expect("server task should finish");
    }

    #[test]
    fn test_ordered_resolved_addrs_prefers_ipv4() {
        let addrs = vec![
            "[::1]:443"
                .parse::<SocketAddr>()
                .expect("ipv6 should parse"),
            "127.0.0.1:443"
                .parse::<SocketAddr>()
                .expect("ipv4 should parse"),
        ];

        let ordered = ordered_resolved_addrs(&addrs);

        assert!(!ordered[0].ip().is_ipv6());
        assert!(ordered[1].ip().is_ipv6());
    }
}
