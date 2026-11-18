pub(crate) fn normalized_severity_label(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "unknown",
    }
}

pub(crate) fn severity_label_rank(severity: &str) -> usize {
    match normalized_severity_label(severity) {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::{normalized_severity_label, severity_label_rank};

    #[test]
    fn normalizes_known_and_unknown_severities() {
        assert_eq!(normalized_severity_label("CRITICAL"), "critical");
        assert_eq!(normalized_severity_label("unexpected"), "unknown");
    }

    #[test]
    fn unknown_severities_sort_after_known_severities() {
        assert_eq!(severity_label_rank("info"), 4);
        assert_eq!(severity_label_rank("unexpected"), 5);
    }
}
