use colored::*;

pub(crate) fn format_bool_indicator(value: bool, yes_text: &str, no_text: &str) -> ColoredString {
    if value {
        format!("Y {}", yes_text).green()
    } else {
        format!("X {}", no_text).red()
    }
}

pub(crate) fn format_status_indicator(value: bool) -> ColoredString {
    if value { "Y".green() } else { "X".red() }
}

pub(crate) fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

pub(crate) fn print_section_header(title: &str) {
    println!("\n{}", title.cyan().bold());
    println!("{}", "=".repeat(50));
}
