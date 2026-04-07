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
