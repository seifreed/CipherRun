#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputPresentationMode {
    #[default]
    Normal,
    DnsOnly,
    ResponseOnly,
}

impl OutputPresentationMode {
    pub fn is_dns_only(self) -> bool {
        matches!(self, Self::DnsOnly)
    }

    pub fn is_response_only(self) -> bool {
        matches!(self, Self::ResponseOnly)
    }

    /// Whether this mode emits machine-readable data to stdout.
    ///
    /// In these modes scan progress must be suppressed so stdout carries only
    /// the requested data (e.g. `--dns` for piping a clean list of domains).
    pub fn suppresses_progress(self) -> bool {
        matches!(self, Self::DnsOnly | Self::ResponseOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::OutputPresentationMode;

    #[test]
    fn test_machine_output_modes_suppress_progress() {
        assert!(OutputPresentationMode::DnsOnly.suppresses_progress());
        assert!(OutputPresentationMode::ResponseOnly.suppresses_progress());
    }

    #[test]
    fn test_normal_mode_keeps_progress() {
        assert!(!OutputPresentationMode::Normal.suppresses_progress());
    }
}
