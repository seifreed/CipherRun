// HTTP module - HTTP security headers testing

pub mod headers;
pub mod headers_advanced;
pub mod hsts_preload;
pub mod tester;

#[cfg(test)]
mod tests {
    use super::headers::IssueSeverity;

    #[test]
    fn test_issue_severity_colored_display() {
        let display = IssueSeverity::High.colored_display().to_string();
        assert!(display.contains("HIGH"));
    }

    #[test]
    fn test_issue_severity_colored_display_low() {
        let display = IssueSeverity::Low.colored_display().to_string();
        assert!(display.contains("LOW"));
    }
}
