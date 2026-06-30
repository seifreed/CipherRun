use super::*;

#[tokio::test]
async fn test_split_target_host_port_hostname() {
    let (hostname, port) =
        split_target_host_port("example.com").expect("test assertion should succeed");
    assert_eq!(hostname, "example.com");
    assert_eq!(port, None);
}

#[tokio::test]
async fn test_split_target_host_port_with_port() {
    let (hostname, port) =
        split_target_host_port("example.com:8443").expect("test assertion should succeed");
    assert_eq!(hostname, "example.com");
    assert_eq!(port, Some(8443));
}

#[test]
fn test_split_target_host_port_trims_outer_whitespace() {
    let (hostname, port) =
        split_target_host_port("  example.com:8443\t").expect("target should be trimmed");
    assert_eq!(hostname, "example.com");
    assert_eq!(port, Some(8443));
}

#[tokio::test]
async fn test_split_target_host_port_url() {
    let (hostname, port) =
        split_target_host_port("https://example.com:8443").expect("test assertion should succeed");
    assert_eq!(hostname, "example.com");
    assert_eq!(port, Some(8443));
}

#[test]
fn test_split_target_host_port_uses_known_url_default_ports() {
    let (hostname, port) = split_target_host_port("http://example.com")
        .expect("HTTP URL should parse with known default port");
    assert_eq!(hostname, "example.com");
    assert_eq!(port, Some(80));

    let (hostname, port) = split_target_host_port("https://example.com")
        .expect("HTTPS URL should parse with known default port");
    assert_eq!(hostname, "example.com");
    assert_eq!(port, Some(443));
}

#[tokio::test]
async fn test_parse_target_ip() {
    let target = Target::parse("93.184.216.34:443")
        .await
        .expect("test assertion should succeed");
    assert_eq!(target.hostname, "93.184.216.34");
    assert_eq!(target.port, 443);
    assert_eq!(target.ip_addresses.len(), 1);
}

#[tokio::test]
async fn test_parse_target_raw_ipv6_without_port() {
    let target = Target::parse("2001:4860:4860::8888")
        .await
        .expect("test assertion should succeed");
    assert_eq!(target.hostname, "2001:4860:4860::8888");
    assert_eq!(target.port, 443);
    assert_eq!(target.ip_addresses.len(), 1);
}

#[tokio::test]
async fn test_parse_target_bracketed_ipv6_with_port() {
    let target = Target::parse("[2001:4860:4860::8888]:443")
        .await
        .expect("test assertion should succeed");
    assert_eq!(target.hostname, "2001:4860:4860::8888");
    assert_eq!(target.port, 443);
    assert_eq!(target.ip_addresses.len(), 1);
}

#[tokio::test]
async fn test_connect_with_timeout_maps_connection_refused() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener should expose addr");
    drop(listener);

    let err = connect_with_timeout(addr, std::time::Duration::from_millis(100), None)
        .await
        .expect_err("closed port should be refused");

    assert!(matches!(err, crate::TlsError::ConnectionRefused { .. }));
}

#[test]
fn test_split_target_host_port_rejects_extra_colons() {
    let err = split_target_host_port("example.com:443:extra")
        .expect_err("should reject malformed host:port input");
    assert!(
        err.to_string()
            .contains("Invalid target format: use [IPv6]:port")
    );
}

#[test]
fn test_split_target_host_port_rejects_bracketed_hostname() {
    let err = split_target_host_port("[example.com]:443")
        .expect_err("bracketed syntax should only accept IPv6 literals");
    assert!(
        err.to_string()
            .contains("Bracketed targets must contain an IPv6 address")
    );
}

#[test]
fn test_split_target_host_port_rejects_bracketed_ipv4() {
    let err = split_target_host_port("[192.0.2.1]:443")
        .expect_err("bracketed syntax should only accept IPv6 literals");
    assert!(
        err.to_string()
            .contains("Bracketed targets must contain an IPv6 address")
    );
}

#[tokio::test]
async fn test_parse_target_with_explicit_port_override() {
    let target = Target::parse_with_port_override("93.184.216.34:443", Some(8443))
        .await
        .expect("test assertion should succeed");
    assert_eq!(target.hostname, "93.184.216.34");
    assert_eq!(target.port, 8443);
}

#[test]
fn test_canonical_target_brackets_ipv6() {
    assert_eq!(canonical_target("2001:db8::1", 443), "[2001:db8::1]:443");
}

#[test]
fn test_canonical_target_strips_existing_brackets() {
    assert_eq!(canonical_target("[2001:db8::1]", 443), "[2001:db8::1]:443");
}

#[test]
fn test_sni_hostname_for_target_omits_ip_literals_without_override() {
    assert_eq!(sni_hostname_for_target("93.184.216.34", None), None);
    assert_eq!(sni_hostname_for_target("2001:db8::1", None), None);
    assert_eq!(
        sni_hostname_for_target("example.com", None),
        Some("example.com".to_string())
    );
}

#[test]
fn test_sni_hostname_for_target_prefers_override() {
    assert_eq!(
        sni_hostname_for_target("93.184.216.34", Some("sni.example")),
        Some("sni.example".to_string())
    );
}

#[test]
fn test_starttls_port_detection() {
    assert!(is_starttls_port(25)); // SMTP
    assert!(is_starttls_port(143)); // IMAP
    assert!(!is_starttls_port(443)); // HTTPS
    assert!(!is_starttls_port(465)); // SMTPS
}

#[test]
fn test_default_starttls_protocol() {
    assert_eq!(default_starttls_protocol(25), Some("smtp"));
    assert_eq!(default_starttls_protocol(143), Some("imap"));
    assert_eq!(default_starttls_protocol(443), None);
}

#[test]
fn test_with_ips_valid() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec!["93.184.216.34".parse().unwrap()],
    );
    assert!(target.is_ok());
    let target = target.unwrap();
    assert_eq!(target.hostname, "example.com");
    assert_eq!(target.port, 443);
    assert_eq!(target.ip_addresses.len(), 1);
}

#[test]
fn test_with_ips_empty_fails() {
    let result = Target::with_ips("example.com".to_string(), 443, vec![]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("at least one IP"));
}

#[test]
fn test_with_ips_empty_hostname_fails() {
    let result = Target::with_ips(
        " \t ".to_string(),
        443,
        vec!["93.184.216.34".parse().unwrap()],
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hostname"));
}

#[test]
fn test_deserialize_target_empty_ips_fails() {
    let result = serde_json::from_str::<Target>(
        r#"{"hostname":"example.com","port":443,"ip_addresses":[]}"#,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("at least one IP"));
}

#[test]
fn test_deserialize_target_empty_hostname_fails() {
    let result = serde_json::from_str::<Target>(
        r#"{"hostname":"","port":443,"ip_addresses":["93.184.216.34"]}"#,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hostname"));
}

#[test]
fn test_primary_ip_and_socket_addrs() {
    let ip: IpAddr = "192.0.2.10".parse().expect("test assertion should succeed");
    let target = Target::with_ips("example.com".to_string(), 8443, vec![ip])
        .expect("test assertion should succeed");
    assert_eq!(target.primary_ip().expect("primary IP should exist"), ip);
    let addrs = target.socket_addrs();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].ip(), ip);
    assert_eq!(addrs[0].port(), 8443);
}

#[test]
fn test_socket_addrs_multiple_ips() {
    let ips = vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()];
    let target = Target::with_ips("example.com".to_string(), 443, ips.clone())
        .expect("test assertion should succeed");
    let addrs = target.socket_addrs();
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0].ip(), ips[0]);
    assert_eq!(addrs[1].ip(), ips[1]);
}

#[tokio::test]
async fn test_cipher_support_outcome_closed_port_is_inconclusive() {
    let target = Target::with_ips(
        "example.com".to_string(),
        9,
        vec!["127.0.0.1".parse().expect("valid IP")],
    )
    .expect("test assertion should succeed");

    let outcome = test_cipher_support_outcome(&target, "AES128-SHA", false, 1)
        .await
        .expect("test assertion should succeed");

    assert_eq!(outcome, CipherSupportOutcome::Inconclusive);
}

#[tokio::test]
async fn test_cipher_support_outcome_closed_handshake_is_inconclusive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test assertion should succeed");
    let port = listener
        .local_addr()
        .expect("test assertion should succeed")
        .port();
    let accept_task = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().expect("valid IP")],
    )
    .expect("test assertion should succeed");

    let outcome = test_cipher_support_outcome(&target, "AES128-SHA", false, 1)
        .await
        .expect("test assertion should succeed");
    accept_task.await.expect("test assertion should succeed");

    assert_eq!(outcome, CipherSupportOutcome::Inconclusive);
}

#[tokio::test]
async fn test_cipher_support_outcome_ssl3_setup_failure_is_inconclusive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test assertion should succeed");
    let port = listener
        .local_addr()
        .expect("test assertion should succeed")
        .port();
    let accept_task = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().expect("valid IP")],
    )
    .expect("test assertion should succeed");

    let outcome = test_cipher_support_outcome(&target, "EXP-RC4-MD5", true, 1)
        .await
        .expect("test assertion should succeed");
    accept_task.await.expect("test assertion should succeed");

    assert_eq!(outcome, CipherSupportOutcome::Inconclusive);
}

#[tokio::test]
async fn test_vuln_ssl_connection_outcome_closed_port_is_inconclusive() {
    let target = Target::with_ips(
        "example.com".to_string(),
        9,
        vec!["127.0.0.1".parse().expect("valid IP")],
    )
    .expect("test assertion should succeed");

    let outcome = test_vuln_ssl_connection_outcome(
        &target,
        VulnSslConfig::with_ciphers("AES128-SHA").with_timeout(1),
    )
    .await
    .expect("test assertion should succeed");

    assert_eq!(outcome, None);
}

#[tokio::test]
async fn test_vuln_ssl_connection_outcome_handshake_failure_is_inconclusive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test assertion should succeed");
    let port = listener
        .local_addr()
        .expect("test assertion should succeed")
        .port();
    let accept_task = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().expect("valid IP")],
    )
    .expect("test assertion should succeed");

    let outcome =
        test_vuln_ssl_connection_outcome(&target, VulnSslConfig::ssl3_only().with_timeout(1))
            .await
            .expect("test assertion should succeed");
    accept_task.await.expect("test assertion should succeed");

    assert_eq!(outcome, None);
}

#[tokio::test]
async fn test_resolve_hostname_short_circuit_ip() {
    // Use a public IP address (Google DNS) to avoid SSRF validation
    let ips = resolve_hostname("8.8.8.8")
        .await
        .expect("test assertion should succeed");
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], "8.8.8.8".parse::<IpAddr>().unwrap());
}

#[test]
fn test_primary_ip() {
    let target = Target::with_ips(
        "example.com".to_string(),
        443,
        vec![
            "93.184.216.34".parse().unwrap(),
            "93.184.216.35".parse().unwrap(),
        ],
    )
    .unwrap();
    let primary: IpAddr = "93.184.216.34".parse().unwrap();
    assert_eq!(
        target.primary_ip().expect("primary IP should exist"),
        primary
    );
}

#[test]
fn test_primary_ip_empty_target_returns_error() {
    let target = Target {
        hostname: "example.com".to_string(),
        port: 443,
        ip_addresses: vec![],
    };
    let err = target
        .primary_ip()
        .expect_err("empty target should not have a primary IP");
    assert!(err.to_string().contains("at least one IP address"));
}

#[test]
fn test_parse_port_invalid() {
    let result = parse_port("not-a-port");
    assert!(result.is_err());
}

#[test]
fn test_parse_port_rejects_zero() {
    let result = parse_port("0");
    assert!(result.is_err());
}

#[test]
fn test_parse_port_valid() {
    let port = parse_port("443").expect("test assertion should succeed");
    assert_eq!(port, 443);
}

#[test]
fn test_default_starttls_protocol_additional_ports() {
    assert_eq!(default_starttls_protocol(587), Some("smtp"));
    assert_eq!(default_starttls_protocol(2525), Some("smtp"));
    assert_eq!(default_starttls_protocol(3306), Some("mysql"));
}

#[test]
fn test_starttls_port_and_protocol_mappings() {
    assert!(is_starttls_port(21));
    assert!(is_starttls_port(389));
    assert!(is_starttls_port(587));
    assert_eq!(default_starttls_protocol(21), Some("ftp"));
    assert_eq!(default_starttls_protocol(389), Some("ldap"));
    assert_eq!(default_starttls_protocol(465), None);
}

#[test]
fn test_normalize_dns_hostname_strips_single_trailing_dot() {
    assert_eq!(
        normalize_dns_hostname("example.com.".to_string()),
        "example.com"
    );
}

#[test]
fn test_normalize_dns_hostname_leaves_dotless_name_untouched() {
    assert_eq!(
        normalize_dns_hostname("example.com".to_string()),
        "example.com"
    );
}

#[test]
fn test_normalize_dns_hostname_preserves_ip_literal() {
    assert_eq!(normalize_dns_hostname("192.0.2.1".to_string()), "192.0.2.1");
}

#[test]
fn test_normalize_dns_hostname_keeps_bare_root_dot() {
    // "." is not a scannable host; leave it so resolution fails loudly rather
    // than collapsing to an empty hostname.
    assert_eq!(normalize_dns_hostname(".".to_string()), ".");
}

#[test]
fn test_server_name_for_hostname_accepts_normalized_fqdn() {
    // After normalization a rooted FQDN must yield a valid rustls ServerName.
    let normalized = normalize_dns_hostname("example.com.".to_string());
    assert!(server_name_for_hostname(&normalized).is_ok());
}

#[test]
fn test_with_ips_normalizes_rooted_fqdn_hostname() {
    use std::net::{IpAddr, Ipv4Addr};
    let target = Target::with_ips(
        "example.com.".to_string(),
        443,
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
    )
    .expect("valid target");
    // The --ip override and custom-resolver paths build Targets via with_ips;
    // the rooted FQDN must be canonicalized identically to the DNS path.
    assert_eq!(target.hostname, "example.com");
}
