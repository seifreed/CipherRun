use super::ValidationError;
use std::net::IpAddr;

/// Maximum length for hostname (RFC 1035)
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum length for label in hostname (RFC 1035)
const MAX_LABEL_LENGTH: usize = 63;

/// Validate hostname according to RFC 1035 and RFC 1123
///
/// # Security Requirements
/// - Prevents command injection via shell metacharacters
/// - Enforces DNS hostname format
/// - Rejects path separators and special characters
/// - Validates length constraints per RFC 1035
pub fn validate_hostname(hostname: &str) -> std::result::Result<(), ValidationError> {
    if hostname.is_empty() {
        return Err(ValidationError::InvalidHostname(
            "Hostname cannot be empty".to_string(),
        ));
    }

    if hostname.len() > MAX_HOSTNAME_LENGTH {
        return Err(ValidationError::InvalidHostname(format!(
            "Hostname too long (max {} characters)",
            MAX_HOSTNAME_LENGTH
        )));
    }

    // Check for dangerous characters that could enable command injection
    let dangerous_chars = [
        '|', '&', ';', '$', '`', '\n', '\r', '<', '>', '(', ')', '{', '}', '\\', '\'', '"', ' ',
    ];
    for ch in dangerous_chars.iter() {
        if hostname.contains(*ch) {
            return Err(ValidationError::InvalidHostname(format!(
                "Hostname contains forbidden character: '{}'",
                ch
            )));
        }
    }

    // Check for path separators
    if hostname.contains('/') || hostname.contains('\\') {
        return Err(ValidationError::InvalidHostname(
            "Hostname cannot contain path separators".to_string(),
        ));
    }

    // Validate as either IP address or DNS hostname
    if hostname.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // Validate DNS hostname format
    let labels: Vec<&str> = hostname.split('.').collect();

    if labels.is_empty() {
        return Err(ValidationError::InvalidHostname(
            "Invalid hostname format".to_string(),
        ));
    }

    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL_LENGTH {
            return Err(ValidationError::InvalidHostname(format!(
                "Label '{}' has invalid length (must be 1-{} characters)",
                label, MAX_LABEL_LENGTH
            )));
        }

        let label_char_count = label.chars().count();
        for (i, ch) in label.chars().enumerate() {
            let is_first = i == 0;
            let is_last = i == label_char_count - 1;

            let is_valid = ch.is_ascii_alphanumeric() || (ch == '-' && !is_first && !is_last);
            if !is_valid {
                return Err(ValidationError::InvalidHostname(format!(
                    "Label '{}' contains invalid character or invalid position for hyphen",
                    label
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hostname_valid() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("192.168.1.1").is_ok());
        assert!(validate_hostname("localhost").is_ok());
        assert!(validate_hostname("test-server-01.example.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_invalid() {
        assert!(validate_hostname("example.com; rm -rf /").is_err());
        assert!(validate_hostname("example.com|whoami").is_err());
        assert!(validate_hostname("example.com`id`").is_err());
        assert!(validate_hostname("example.com$(whoami)").is_err());
        assert!(validate_hostname("../../etc/passwd").is_err());
        assert!(validate_hostname("example.com/../../etc").is_err());
        assert!(validate_hostname("example com").is_err());
        assert!(validate_hostname("example\ncom").is_err());
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname(&"a".repeat(300)).is_err());
    }

    #[test]
    fn test_validate_hostname_label_length_boundaries() {
        let valid_label = "a".repeat(63);
        let valid_host = format!("{}.com", valid_label);
        assert!(validate_hostname(&valid_host).is_ok());

        let invalid_label = "b".repeat(64);
        let invalid_host = format!("{}.com", invalid_label);
        assert!(validate_hostname(&invalid_host).is_err());
    }

    #[test]
    fn test_validate_hostname_hyphen_positions() {
        assert!(validate_hostname("-example.com").is_err());
        assert!(validate_hostname("example-.com").is_err());
        assert!(validate_hostname("exa-mple.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_rejects_empty_label() {
        assert!(validate_hostname("example..com").is_err());
    }
}
