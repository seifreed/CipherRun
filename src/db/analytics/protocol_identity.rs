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
