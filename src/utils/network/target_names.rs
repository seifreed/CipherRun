use crate::Result;
use crate::error::TlsError;
use crate::security::input_validation::looks_like_obfuscated_ip;
use std::net::{IpAddr, Ipv6Addr};

/// Canonical target formatter.
///
/// Hostnames and IPv4 addresses are rendered as `host:port`.
/// IPv6 addresses are rendered as `[host]:port` to avoid ambiguity.
pub fn canonical_target(hostname: &str, port: u16) -> String {
    let hostname = unbracket_host(hostname);

    if hostname.parse::<IpAddr>().is_ok() && hostname.contains(':') {
        format!("[{}]:{}", hostname, port)
    } else {
        format!("{}:{}", hostname, port)
    }
}

/// Build a TLS server name from a hostname or IP literal.
///
/// This accepts DNS names, bracketed IPv6 literals, and raw IP literals.
/// IP targets are converted to `ServerName::IpAddress` so they can be used
/// in TLS handshakes without being treated as invalid DNS names.
pub fn server_name_for_hostname(
    hostname: &str,
) -> crate::Result<rustls_pki_types::ServerName<'static>> {
    let hostname = normalize_dns_hostname(unbracket_host(hostname).to_string());

    if looks_like_obfuscated_ip(&hostname) {
        return Err(crate::error::TlsError::ParseError {
            message: "Invalid DNS name".into(),
        });
    }

    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(rustls_pki_types::ServerName::from(ip).to_owned());
    }

    rustls_pki_types::ServerName::try_from(hostname.to_string()).map_err(|_| {
        crate::error::TlsError::ParseError {
            message: "Invalid DNS name".into(),
        }
    })
}

/// Canonicalize a DNS hostname by removing a single trailing dot.
///
/// `example.com.` is a valid absolute (rooted) FQDN and resolves fine, but the
/// rooted form must not reach the TLS layer: the SNI extension (RFC 6066
/// `HostName`) forbids a trailing dot, rustls' DNS `ServerName` rejects it, and
/// a certificate's SAN never carries one — so leaving it on causes the TLS 1.3
/// probe to fail and a spurious hostname mismatch. IP literals (which never end
/// in a dot) and the bare root `.` are left untouched.
pub fn normalize_dns_hostname(hostname: String) -> String {
    if hostname.parse::<IpAddr>().is_ok() {
        return hostname;
    }
    if let Some(stripped) = hostname.strip_suffix('.')
        && stripped.parse::<IpAddr>().is_ok()
    {
        return hostname;
    }
    match hostname.strip_suffix('.') {
        Some(stripped) if !stripped.is_empty() => stripped.to_string(),
        _ => hostname,
    }
}

/// Choose the hostname to use for an SNI extension.
///
/// Explicit overrides win. Otherwise, raw IP literals are omitted because SNI
/// is defined for DNS hostnames, not address literals.
pub fn sni_hostname_for_target(hostname: &str, override_hostname: Option<&str>) -> Option<String> {
    if let Some(override_hostname) = override_hostname {
        return Some(override_hostname.to_string());
    }

    let hostname = unbracket_host(hostname);

    if hostname.parse::<IpAddr>().is_ok() || looks_like_obfuscated_ip(hostname) {
        None
    } else {
        Some(hostname.to_string())
    }
}

/// Display a hostname without a port.
///
/// IPv6 literals are bracketed so the display remains unambiguous.
pub fn display_target_host(hostname: &str) -> String {
    let hostname = unbracket_host(hostname);

    if hostname.contains(':') {
        format!("[{}]", hostname)
    } else {
        hostname.to_string()
    }
}

/// Split a target string into hostname and optional port without resolving DNS.
///
/// This parser accepts URLs, bracketed IPv6, raw IPv6 literals, and host[:port]
/// inputs. Raw IPv6 literals without brackets are treated as host-only values.
pub fn split_target_host_port(input: &str) -> Result<(String, Option<u16>)> {
    let input = input.trim();
    if input.trim().is_empty() {
        crate::tls_bail!("Target cannot be empty");
    }

    if input.contains("://") {
        return split_url_target(input);
    }

    if let Some(rest) = input.strip_prefix('[') {
        return split_bracketed_target(rest);
    }

    if let Ok(ipv6) = input.parse::<Ipv6Addr>() {
        return Ok((ipv6.to_string(), None));
    }

    if let Some((host, port_str)) = input.rsplit_once(':')
        && !host.contains(':')
    {
        let host = host.trim();
        if host.is_empty() {
            crate::tls_bail!("Target host cannot be empty");
        }
        return Ok((host.to_string(), Some(parse_port(port_str.trim())?)));
    }

    if input.contains(':') {
        crate::tls_bail!("Invalid target format: use [IPv6]:port for IPv6 addresses with ports");
    }

    Ok((input.to_string(), None))
}

/// Parse port from string.
pub fn parse_port(port_str: &str) -> Result<u16> {
    let port = port_str
        .parse::<u16>()
        .map_err(|e| TlsError::Other(format!("Invalid port number: {e}")))?;
    if port == 0 {
        crate::tls_bail!("Port must be between 1 and 65535");
    }
    Ok(port)
}

fn split_url_target(input: &str) -> Result<(String, Option<u16>)> {
    let url = url::Url::parse(input)?;
    if !matches!(url.scheme(), "http" | "https") {
        crate::tls_bail!("Unsupported target URL scheme: {}", url.scheme());
    }
    if !url.username().is_empty() || url.password().is_some() {
        crate::tls_bail!("Target URL must not contain credentials");
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        crate::tls_bail!("Target URL must not include a path, query, or fragment");
    }
    let host = url
        .host_str()
        .ok_or_else(|| TlsError::Other("No hostname in URL".to_string()))?
        .to_string();
    if matches!(url.port(), Some(0)) {
        crate::tls_bail!("Port must be between 1 and 65535");
    }
    Ok((host, url.port_or_known_default()))
}

fn split_bracketed_target(rest: &str) -> Result<(String, Option<u16>)> {
    let Some(bracket_end) = rest.find(']') else {
        return Err(TlsError::Other(
            "Invalid IPv6 address format - missing closing bracket".to_string(),
        ));
    };

    let (hostname, suffix) = rest.split_at(bracket_end);
    if hostname.parse::<Ipv6Addr>().is_err() {
        crate::tls_bail!("Bracketed targets must contain an IPv6 address");
    }
    let hostname = hostname.to_string();
    let suffix = suffix.strip_prefix(']').unwrap_or(suffix);
    if suffix.is_empty() {
        return Ok((hostname, None));
    }
    if let Some(port_str) = suffix.strip_prefix(':') {
        return Ok((hostname, Some(parse_port(port_str.trim())?)));
    }
    Err(TlsError::Other(
        "Invalid format after IPv6 address".to_string(),
    ))
}

fn unbracket_host(hostname: &str) -> &str {
    hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname)
}
