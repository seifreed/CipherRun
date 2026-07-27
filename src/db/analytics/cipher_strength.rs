pub(crate) fn cipher_strength_category(strength: &str) -> &'static str {
    match strength.to_ascii_lowercase().as_str() {
        "weak" | "low" | "export" | "null" => "weak",
        "medium" => "medium",
        "strong" | "high" => "strong",
        _ => "unknown",
    }
}
