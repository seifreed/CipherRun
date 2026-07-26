use super::MIN_SECURE_DH_BITS;

/// Outcome of probing a single cipher for connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogjamProbeStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

/// Outcome of measuring the server's ephemeral DH parameter size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WeakDhStatus {
    /// DH parameters below the secure minimum; carries the measured key size.
    Weak {
        bits: u32,
    },
    Strong,
    Inconclusive,
}

impl WeakDhStatus {
    fn is_weak(self) -> bool {
        matches!(self, Self::Weak { .. })
    }

    fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }
}

/// LOGJAM test result.
#[derive(Debug, Clone)]
pub struct LogjamTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub export_dh_supported: bool,
    pub weak_dh_params: bool,
    pub dhe_ciphers: Vec<String>,
    pub details: String,
}

impl LogjamTestResult {
    pub(super) fn from_probe_results(
        export_dh: bool,
        export_inconclusive: bool,
        weak_dh: WeakDhStatus,
        dhe_ciphers: Vec<String>,
        dhe_inconclusive: bool,
    ) -> Self {
        let weak_dh_bits = match weak_dh {
            WeakDhStatus::Weak { bits } => Some(bits),
            _ => None,
        };
        let weak_dh_params = weak_dh.is_weak();
        let vulnerable = export_dh || weak_dh_params;
        let inconclusive =
            !vulnerable && (export_inconclusive || weak_dh.is_inconclusive() || dhe_inconclusive);

        let details = details_for_result(
            vulnerable,
            inconclusive,
            export_dh,
            weak_dh_bits,
            &dhe_ciphers,
        );

        Self {
            vulnerable,
            inconclusive,
            export_dh_supported: export_dh,
            weak_dh_params,
            dhe_ciphers,
            details,
        }
    }
}

fn details_for_result(
    vulnerable: bool,
    inconclusive: bool,
    export_dh: bool,
    weak_dh_bits: Option<u32>,
    dhe_ciphers: &[String],
) -> String {
    if vulnerable {
        let mut parts: Vec<String> = Vec::new();
        if export_dh {
            parts.push("Export-grade DH supported".to_string());
        }
        match weak_dh_bits {
            Some(bits) if bits > 0 => parts.push(format!(
                "Weak DH parameters ({} bits, below {}-bit minimum)",
                bits, MIN_SECURE_DH_BITS
            )),
            Some(_) => parts
                .push("Weak DH parameters (rejected by the TLS library as too small)".to_string()),
            None => {}
        }
        format!("Vulnerable to LOGJAM (CVE-2015-4000): {}", parts.join(", "))
    } else if inconclusive {
        "LOGJAM test inconclusive - unable to determine DH cipher/parameter support".to_string()
    } else if !dhe_ciphers.is_empty() {
        "Not vulnerable - DHE supported with strong parameters".to_string()
    } else {
        "Not vulnerable - DHE not supported".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_dh_probe_marks_result_vulnerable() {
        let result = LogjamTestResult::from_probe_results(
            false,
            false,
            WeakDhStatus::Weak { bits: 1024 },
            vec!["DHE-RSA-AES128-SHA".to_string()],
            false,
        );

        assert!(result.vulnerable);
        assert!(result.weak_dh_params);
        assert!(result.details.contains("1024 bits"));
    }

    #[test]
    fn inconclusive_probe_marks_clean_result_inconclusive() {
        let result = LogjamTestResult::from_probe_results(
            false,
            true,
            WeakDhStatus::Strong,
            Vec::new(),
            false,
        );

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
    }
}
