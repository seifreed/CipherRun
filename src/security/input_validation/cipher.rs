use super::ValidationError;

/// Validate OpenSSL cipher string
///
/// # Security Requirements
/// - Allows standard cipher names and OpenSSL cipher string syntax
/// - Rejects shell metacharacters
/// - Prevents command injection
pub fn validate_cipher(cipher: &str) -> std::result::Result<(), ValidationError> {
    if cipher.is_empty() {
        return Err(ValidationError::InvalidCipher(
            "Cipher cannot be empty".to_string(),
        ));
    }

    if cipher.len() > 512 {
        return Err(ValidationError::InvalidCipher(
            "Cipher string too long".to_string(),
        ));
    }

    for ch in cipher.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | ':' | '!' | '+' | '@' => continue,
            _ => {
                return Err(ValidationError::InvalidCipher(format!(
                    "Cipher contains invalid character: '{}'",
                    ch
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
    fn test_validate_cipher_valid() {
        assert!(validate_cipher("AES256-GCM-SHA384").is_ok());
        assert!(validate_cipher("ECDHE-RSA-AES256-GCM-SHA384").is_ok());
        assert!(validate_cipher("HIGH:!aNULL:!MD5").is_ok());
        assert!(validate_cipher("TLS_AES_256_GCM_SHA384").is_ok());
    }

    #[test]
    fn test_validate_cipher_invalid() {
        assert!(validate_cipher("AES256; rm -rf /").is_err());
        assert!(validate_cipher("AES256|whoami").is_err());
        assert!(validate_cipher("AES256`id`").is_err());
        assert!(validate_cipher("").is_err());
    }
}
