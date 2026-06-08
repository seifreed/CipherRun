// Shared formatting utilities for alert channels

use crate::monitor::detector::ChangeSeverity;

/// Shared severity-to-color mapping for alert channels.
pub fn severity_color(severity: &ChangeSeverity) -> &'static str {
    match severity {
        ChangeSeverity::Critical => "#dc3545",
        ChangeSeverity::High => "#fd7e14",
        ChangeSeverity::Medium => "#ffc107",
        ChangeSeverity::Low => "#0dcaf0",
        ChangeSeverity::Info => "#6c757d",
    }
}

/// HTML-escape a string for safe interpolation into email alert bodies.
///
/// Certificate-derived values (issuer/subject DNs, SANs, serials) and scan
/// error/validation strings are attacker-influenced: a monitored server can
/// present a certificate whose fields contain markup. Without escaping, those
/// values would inject arbitrary HTML into the operator's inbox.
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Shared severity-to-emoji mapping for messaging channels.
pub fn severity_emoji(severity: &ChangeSeverity) -> &'static str {
    match severity {
        ChangeSeverity::Critical => ":rotating_light:",
        ChangeSeverity::High => ":warning:",
        ChangeSeverity::Medium => ":large_orange_diamond:",
        ChangeSeverity::Low => ":information_source:",
        ChangeSeverity::Info => ":white_check_mark:",
    }
}
