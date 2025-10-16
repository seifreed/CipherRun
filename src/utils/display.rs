// Display utilities for enhanced output formatting

use colored::*;

/// Display configuration
#[derive(Debug, Clone)]
pub struct DisplayConfig {
    pub colorblind_mode: bool,
    pub show_rfc_names: bool,
    pub show_openssl_names: bool,
    pub show_each: bool,
}

impl DisplayConfig {
    /// Create new display config from CLI args
    pub fn from_args(colorblind: bool, cipher_mapping: Option<&str>, show_each: bool) -> Self {
        let (show_rfc_names, show_openssl_names) = match cipher_mapping {
            Some("no-openssl") => (true, false),
            Some("no-rfc") => (false, true),
            _ => (true, true), // Show both by default
        };

        Self {
            colorblind_mode: colorblind,
            show_rfc_names,
            show_openssl_names,
            show_each,
        }
    }

    /// Get cipher name to display
    pub fn format_cipher_name(&self, openssl_name: &str, rfc_name: &str) -> String {
        match (self.show_openssl_names, self.show_rfc_names) {
            (true, true) => format!("{} ({})", openssl_name, rfc_name),
            (true, false) => openssl_name.to_string(),
            (false, true) => rfc_name.to_string(),
            (false, false) => openssl_name.to_string(), // Fallback
        }
    }

    /// Get success color (green or blue for colorblind)
    pub fn success_color<T: Colorize>(&self, text: T) -> ColoredString {
        if self.colorblind_mode {
            text.blue()
        } else {
            text.green()
        }
    }

    /// Get warning color (yellow or cyan for colorblind)
    pub fn warning_color<T: Colorize>(&self, text: T) -> ColoredString {
        if self.colorblind_mode {
            text.cyan()
        } else {
            text.yellow()
        }
    }

    /// Get error color (red or magenta for colorblind)
    pub fn error_color<T: Colorize>(&self, text: T) -> ColoredString {
        if self.colorblind_mode {
            text.magenta()
        } else {
            text.red()
        }
    }

    /// Get info color (cyan or normal for colorblind)
    pub fn info_color<T: Colorize>(&self, text: T) -> ColoredString {
        if self.colorblind_mode {
            text.normal()
        } else {
            text.cyan()
        }
    }

    /// Get critical color (red bold or magenta bold for colorblind)
    pub fn critical_color<T: Colorize>(&self, text: T) -> ColoredString {
        if self.colorblind_mode {
            text.magenta().bold()
        } else {
            text.red().bold()
        }
    }
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            colorblind_mode: false,
            show_rfc_names: true,
            show_openssl_names: true,
            show_each: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_config_default() {
        let config = DisplayConfig::default();
        assert!(!config.colorblind_mode);
        assert!(config.show_rfc_names);
        assert!(config.show_openssl_names);
        assert!(!config.show_each);
    }

    #[test]
    fn test_cipher_name_formatting() {
        let config = DisplayConfig::default();
        let name =
            config.format_cipher_name("ECDHE-RSA-AES128-SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        assert!(name.contains("ECDHE-RSA-AES128-SHA"));
        assert!(name.contains("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
    }

    #[test]
    fn test_no_openssl_mapping() {
        let config = DisplayConfig::from_args(false, Some("no-openssl"), false);
        assert!(!config.show_openssl_names);
        assert!(config.show_rfc_names);

        let name =
            config.format_cipher_name("ECDHE-RSA-AES128-SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        assert_eq!(name, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
    }

    #[test]
    fn test_no_rfc_mapping() {
        let config = DisplayConfig::from_args(false, Some("no-rfc"), false);
        assert!(config.show_openssl_names);
        assert!(!config.show_rfc_names);

        let name =
            config.format_cipher_name("ECDHE-RSA-AES128-SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        assert_eq!(name, "ECDHE-RSA-AES128-SHA");
    }

    #[test]
    fn test_colorblind_mode() {
        let config = DisplayConfig::from_args(true, None, false);
        assert!(config.colorblind_mode);

        // Verify color methods work (we can't easily test actual colors)
        let _ = config.success_color("test");
        let _ = config.error_color("test");
        let _ = config.warning_color("test");
    }
}
