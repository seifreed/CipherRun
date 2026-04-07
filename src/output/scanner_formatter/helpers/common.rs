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
    if s.len() > max_len && max_len > 3 {
        let target = max_len - 3;
        // Find a safe UTF-8 char boundary at or before `target`
        let boundary = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= target)
            .last()
            .unwrap_or(0);
        format!("{}...", &s[..boundary])
    } else {
        s.to_string()
    }
}

pub(crate) fn print_section_header(title: &str) {
    println!("\n{}", title.cyan().bold());
    println!("{}", "=".repeat(50));
}
