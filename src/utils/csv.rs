/// Quote a CSV cell and neutralize spreadsheet formulas.
pub(crate) fn formula_safe_csv_cell(value: &str) -> String {
    let trimmed = value.trim();
    let safe = if trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r')
    {
        format!("'{trimmed}")
    } else {
        trimmed.to_string()
    };

    format!("\"{}\"", safe.replace('"', "\"\""))
}
