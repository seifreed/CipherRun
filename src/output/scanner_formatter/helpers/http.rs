use colored::*;

use crate::http::headers::IssueType;

pub(crate) fn format_http_status(status_code: u16) -> ColoredString {
    let status_str = status_code.to_string();
    if (200..300).contains(&status_code) {
        status_str.green()
    } else if (300..400).contains(&status_code) {
        status_str.yellow()
    } else if status_code >= 400 {
        status_str.red()
    } else {
        status_str.normal()
    }
}

pub(crate) fn format_http_issue_icon(issue_type: &IssueType) -> &'static str {
    match issue_type {
        IssueType::Missing | IssueType::Invalid => "X",
        IssueType::Insecure | IssueType::Weak => "!",
        IssueType::Deprecated => "i",
    }
}

pub(crate) fn format_client_sim_summary(successful: usize, total: usize) -> ColoredString {
    if successful == total {
        format!("{}/{} clients", successful, total).green()
    } else if successful == 0 {
        format!("{}/{} clients", successful, total).red()
    } else {
        format!("{}/{} clients", successful, total).yellow()
    }
}
