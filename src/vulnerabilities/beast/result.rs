use super::BeastProbeStatus;

/// BEAST test result.
#[derive(Debug, Clone)]
pub struct BeastTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub tls10_cbc_supported: bool,
    pub ssl3_cbc_supported: bool,
    pub details: String,
}

impl BeastTestResult {
    pub(super) fn from_probe_statuses(
        tls10_cbc: BeastProbeStatus,
        ssl3_cbc: BeastProbeStatus,
    ) -> Self {
        let vulnerable = tls10_cbc.is_supported() || ssl3_cbc.is_supported();
        let inconclusive =
            !vulnerable && (tls10_cbc.is_inconclusive() || ssl3_cbc.is_inconclusive());

        Self {
            vulnerable,
            inconclusive,
            tls10_cbc_supported: tls10_cbc.is_supported(),
            ssl3_cbc_supported: ssl3_cbc.is_supported(),
            details: details_for_result(vulnerable, inconclusive, tls10_cbc, ssl3_cbc),
        }
    }
}

fn details_for_result(
    vulnerable: bool,
    inconclusive: bool,
    tls10_cbc: BeastProbeStatus,
    ssl3_cbc: BeastProbeStatus,
) -> String {
    if vulnerable {
        let mut parts = Vec::new();
        if tls10_cbc.is_supported() {
            parts.push("TLS 1.0 with CBC ciphers enabled");
        }
        if ssl3_cbc.is_supported() {
            parts.push("SSL 3.0 with CBC ciphers enabled");
        }
        format!("Vulnerable: {}", parts.join(", "))
    } else if inconclusive {
        "BEAST test inconclusive - unable to complete TLS 1.0/SSL 3.0 CBC probes".to_string()
    } else {
        "Not vulnerable - TLS 1.0/SSL 3.0 CBC ciphers not supported".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls10_cbc_support_marks_result_vulnerable() {
        let result = BeastTestResult::from_probe_statuses(
            BeastProbeStatus::Supported,
            BeastProbeStatus::NotSupported,
        );

        assert!(result.vulnerable);
        assert!(result.tls10_cbc_supported);
        assert!(result.details.contains("TLS 1.0"));
    }

    #[test]
    fn inconclusive_clean_probes_mark_result_inconclusive() {
        let result = BeastTestResult::from_probe_statuses(
            BeastProbeStatus::Inconclusive,
            BeastProbeStatus::NotSupported,
        );

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
    }
}
