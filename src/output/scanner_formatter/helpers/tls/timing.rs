use colored::*;

pub(crate) fn format_timing(show_times: bool, time_ms: Option<u64>) -> String {
    if show_times {
        time_ms
            .map(|ms| format!(" ({}ms)", ms).dimmed().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    }
}

pub(crate) fn format_avg_timing(show_times: bool, avg_ms: Option<u64>) -> String {
    if show_times {
        avg_ms
            .map(|ms| format!(" (avg {}ms)", ms).dimmed().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    }
}
