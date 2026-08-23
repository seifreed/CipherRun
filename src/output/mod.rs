// Output module - Output formatting (JSON, CSV, HTML, Terminal)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    JSON,
    JSONPretty,
    CSV,
    HTML,
    Log,
}

pub mod csv;
pub mod hello_export;
pub mod html;
pub mod json;
pub mod junit;
pub mod multi_ip_terminal;
pub mod probe_status;
pub mod sarif;
pub mod scanner_formatter;
pub mod schema;
pub mod xml;

// MEDIUM PRIORITY Features (11-15)
pub mod dns_only;
pub mod response_only;

// Re-export ScannerFormatter for easy access
pub use scanner_formatter::ScannerFormatter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_traits() {
        for (format, debug) in [
            (OutputFormat::Terminal, "Terminal"),
            (OutputFormat::JSON, "JSON"),
            (OutputFormat::JSONPretty, "JSONPretty"),
            (OutputFormat::CSV, "CSV"),
            (OutputFormat::HTML, "HTML"),
            (OutputFormat::Log, "Log"),
        ] {
            let copied = format;
            assert_eq!(format, copied);
            assert_eq!(format!("{format:?}"), debug);
        }

        assert_ne!(OutputFormat::JSON, OutputFormat::CSV);
    }
}
