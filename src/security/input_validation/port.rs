use super::ValidationError;

/// Validate port number
///
/// # Security Requirements
/// - Ensures port is within valid range (1-65535)
/// - Type-safe validation using u16
pub fn validate_port(port: u16) -> std::result::Result<(), ValidationError> {
    if port == 0 {
        return Err(ValidationError::InvalidPort(
            "Port must be between 1 and 65535".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_port() {
        assert!(validate_port(443).is_ok());
        assert!(validate_port(1).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
    }
}
