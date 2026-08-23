/// BREACH test result.
#[derive(Debug, Clone)]
pub struct BreachTestResult {
    pub vulnerable: bool,
    /// True when one or more sub-probes could not complete (TCP/TLS failure
    /// or empty HTTP response). Prevents reporting unreachable servers as
    /// confirmed-not-vulnerable.
    pub inconclusive: bool,
    pub potential_exposure: bool,
    pub compression_enabled: bool,
    pub dynamic_content: bool,
    pub sensitive_data_reflection: bool,
    pub details: String,
}

impl BreachTestResult {
    pub(super) fn from_probe_results(
        compression: Option<bool>,
        dynamic: Option<bool>,
        sensitive: Option<bool>,
    ) -> Self {
        let inconclusive = compression.is_none() || dynamic.is_none() || sensitive.is_none();
        let compression_enabled = compression.unwrap_or(false);
        let dynamic_content = dynamic.unwrap_or(false);
        let sensitive_data_reflection = sensitive.unwrap_or(false);
        let potential_exposure =
            !inconclusive && compression_enabled && dynamic_content && sensitive_data_reflection;

        Self {
            vulnerable: false,
            inconclusive,
            potential_exposure,
            compression_enabled,
            dynamic_content,
            sensitive_data_reflection,
            details: details(
                inconclusive,
                potential_exposure,
                compression_enabled,
                dynamic_content,
                sensitive_data_reflection,
            ),
        }
    }
}

pub(super) fn merge_probe_bool(current: Option<bool>, next: Option<bool>) -> Option<bool> {
    match (current, next) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, _) | (_, None) => None,
        _ => Some(false),
    }
}

fn details(
    inconclusive: bool,
    potential_exposure: bool,
    compression_enabled: bool,
    dynamic_content: bool,
    sensitive_data_reflection: bool,
) -> String {
    if inconclusive {
        "Inconclusive - one or more BREACH probes could not complete (TCP/TLS error or empty HTTP response)".to_string()
    } else if potential_exposure {
        "Potential exposure to BREACH (CVE-2013-3587): HTTP compression and reflection prerequisites observed on GET /. Practical exploitability was not demonstrated.".to_string()
    } else if compression_enabled {
        let mut reasons = Vec::new();
        if !dynamic_content {
            reasons.push("no dynamic content detected");
        }
        if !sensitive_data_reflection {
            reasons.push("no sensitive data reflection detected");
        }
        format!(
            "No BREACH exposure observed on GET /: HTTP compression enabled but {}",
            reasons.join(" and ")
        )
    } else {
        "No BREACH exposure observed on GET /: HTTP compression not enabled".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_true_over_inconclusive() {
        assert_eq!(merge_probe_bool(None, Some(true)), Some(true));
    }

    #[test]
    fn failed_probe_makes_result_inconclusive() {
        let result = BreachTestResult::from_probe_results(None, Some(true), Some(true));

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.details.contains("Inconclusive"));
    }

    #[test]
    fn all_positive_probes_mark_potential_exposure() {
        let result = BreachTestResult::from_probe_results(Some(true), Some(true), Some(true));

        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
        assert!(result.potential_exposure);
        assert!(result.details.contains("Potential exposure to BREACH"));
        assert!(result.details.contains("was not demonstrated"));
    }
}
