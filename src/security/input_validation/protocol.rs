use super::ValidationError;

/// Validate STARTTLS protocol name
///
/// # Security Requirements
/// - Allows only known STARTTLS protocols
/// - Prevents command injection via protocol field
pub fn validate_starttls_protocol(protocol: &str) -> std::result::Result<(), ValidationError> {
    const VALID_PROTOCOLS: &[&str] = &[
        "smtp",
        "pop3",
        "imap",
        "ftp",
        "xmpp",
        "xmpp-server",
        "irc",
        "postgres",
        "mysql",
        "lmtp",
        "nntp",
        "sieve",
        "ldap",
    ];

    if !VALID_PROTOCOLS.contains(&protocol) {
        return Err(ValidationError::InvalidProtocol(format!(
            "Unknown STARTTLS protocol: '{}'. Valid protocols: {}",
            protocol,
            VALID_PROTOCOLS.join(", ")
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_starttls_protocol() {
        assert!(validate_starttls_protocol("smtp").is_ok());
        assert!(validate_starttls_protocol("imap").is_ok());
        assert!(validate_starttls_protocol("invalid").is_err());
        assert!(validate_starttls_protocol("smtp; whoami").is_err());
    }
}
