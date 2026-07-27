pub(crate) fn normalized_protocol_name(protocol: &str) -> String {
    protocol
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '_' && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

pub(crate) fn protocol_identity(protocol: &str) -> String {
    let normalized = normalized_protocol_name(protocol);
    if let Some(version) = normalized.strip_prefix("TLSV") {
        format!("TLS{}", version)
    } else if let Some(version) = normalized.strip_prefix("SSLV") {
        format!("SSL{}", version)
    } else {
        normalized
    }
}

pub(crate) fn is_tls_version(protocol: &str, version: &str) -> bool {
    protocol_identity(protocol) == format!("TLS{}", version)
}

pub(crate) fn is_ssl_protocol(protocol: &str) -> bool {
    matches!(
        protocol_identity(protocol).as_str(),
        "SSL2" | "SSL2.0" | "SSL20" | "SSL3" | "SSL3.0" | "SSL30"
    )
}
