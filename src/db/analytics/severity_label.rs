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
