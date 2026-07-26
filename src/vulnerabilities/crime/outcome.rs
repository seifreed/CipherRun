#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompressionProbeStatus {
    Enabled,
    Disabled,
    Inconclusive,
}

impl CompressionProbeStatus {
    pub(super) fn merge(self, next: Self) -> Self {
        match (self, next) {
            (Self::Enabled, _) | (_, Self::Enabled) => Self::Enabled,
            (Self::Inconclusive, _) | (_, Self::Inconclusive) => Self::Inconclusive,
            _ => Self::Disabled,
        }
    }

    fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }
}

/// CRIME test result
#[derive(Debug, Clone)]
pub struct CrimeTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub tls_compression_enabled: bool,
    pub spdy_compression_enabled: bool,
    pub details: String,
}

impl CrimeTestResult {
    pub(super) fn from_probe_statuses(
        tls_compression: CompressionProbeStatus,
        spdy_compression: CompressionProbeStatus,
    ) -> Self {
        let tls_compression_enabled = tls_compression.is_enabled();
        let spdy_compression_enabled = spdy_compression.is_enabled();
        let vulnerable = tls_compression_enabled || spdy_compression_enabled;
        let inconclusive = !vulnerable
            && (tls_compression.is_inconclusive() || spdy_compression.is_inconclusive());

        Self {
            vulnerable,
            inconclusive,
            tls_compression_enabled,
            spdy_compression_enabled,
            details: details(
                vulnerable,
                inconclusive,
                tls_compression_enabled,
                spdy_compression_enabled,
            ),
        }
    }
}

fn details(
    vulnerable: bool,
    inconclusive: bool,
    tls_compression_enabled: bool,
    spdy_compression_enabled: bool,
) -> String {
    if vulnerable {
        let mut parts = Vec::new();
        if tls_compression_enabled {
            parts.push("TLS compression enabled");
        }
        if spdy_compression_enabled {
            parts.push("SPDY compression enabled");
        }
        format!("Vulnerable to CRIME (CVE-2012-4929): {}", parts.join(", "))
    } else if inconclusive {
        "CRIME test inconclusive - unable to determine TLS/SPDY compression status".to_string()
    } else {
        "Not vulnerable - TLS/SPDY compression disabled".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_status_wins_merge() {
        assert_eq!(
            CompressionProbeStatus::Inconclusive.merge(CompressionProbeStatus::Enabled),
            CompressionProbeStatus::Enabled
        );
    }

    #[test]
    fn inconclusive_status_wins_over_disabled() {
        assert_eq!(
            CompressionProbeStatus::Disabled.merge(CompressionProbeStatus::Inconclusive),
            CompressionProbeStatus::Inconclusive
        );
    }

    #[test]
    fn statuses_build_public_result() {
        let result = CrimeTestResult::from_probe_statuses(
            CompressionProbeStatus::Enabled,
            CompressionProbeStatus::Disabled,
        );

        assert!(result.vulnerable);
        assert!(!result.inconclusive);
        assert!(result.tls_compression_enabled);
        assert!(result.details.contains("TLS compression enabled"));
    }
}
