// Sneaky mode utilities - Reduce traces in target logs

/// Generic User-Agent for sneaky mode (common Firefox on Linux)
pub const SNEAKY_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0";

/// Generic hostname for SMTP/LMTP EHLO/HELO commands
pub const SNEAKY_SMTP_HOSTNAME: &str = "google.com";

/// Generic hostname for other protocols
pub const SNEAKY_GENERIC_HOSTNAME: &str = "localhost";

/// Sneaky mode configuration
#[derive(Debug, Clone, Default)]
pub struct SneakyConfig {
    pub enabled: bool,
}

impl SneakyConfig {
    /// Create new sneaky config
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Get User-Agent to use
    pub fn user_agent(&self) -> &'static str {
        if self.enabled {
            SNEAKY_USER_AGENT
        } else {
            // Default user agent - Chrome on Windows (most common)
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        }
    }

    /// Get hostname to use for SMTP/LMTP
    pub fn smtp_hostname(&self) -> &'static str {
        if self.enabled {
            SNEAKY_SMTP_HOSTNAME
        } else {
            "localhost"
        }
    }

    /// Get generic hostname
    pub fn generic_hostname(&self) -> &'static str {
        if self.enabled {
            SNEAKY_GENERIC_HOSTNAME
        } else {
            "localhost"
        }
    }

    /// Check if we should use sneaky mode
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sneaky_config() {
        let sneaky = SneakyConfig::new(true);
        assert!(sneaky.is_enabled());
        assert_eq!(sneaky.user_agent(), SNEAKY_USER_AGENT);
        assert_eq!(sneaky.smtp_hostname(), SNEAKY_SMTP_HOSTNAME);
    }

    #[test]
    fn test_normal_config() {
        let normal = SneakyConfig::new(false);
        assert!(!normal.is_enabled());
        assert_eq!(
            normal.user_agent(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        );
    }
}
