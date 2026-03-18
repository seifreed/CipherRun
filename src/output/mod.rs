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
pub mod html;
pub mod json;
pub mod multi_ip_terminal;
pub mod probe_status;
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
    fn test_output_format_debug_and_equality() {
        assert_eq!(OutputFormat::JSON, OutputFormat::JSON);
        assert_ne!(OutputFormat::JSON, OutputFormat::CSV);
        assert_eq!(format!("{:?}", OutputFormat::JSONPretty), "JSONPretty");
    }

    #[test]
    fn test_output_format_debug_log() {
        assert_eq!(format!("{:?}", OutputFormat::Log), "Log");
    }

    #[test]
    fn test_output_format_terminal_variant() {
        let format = OutputFormat::Terminal;
        assert_eq!(format, OutputFormat::Terminal);
        assert_eq!(format!("{:?}", format), "Terminal");
    }

    #[test]
    fn test_output_format_copy_semantics() {
        let format = OutputFormat::JSON;
        let copied = format;
        assert_eq!(format, copied);
    }

    #[test]
    fn test_output_format_html_variant() {
        let format = OutputFormat::HTML;
        assert_eq!(format, OutputFormat::HTML);
        assert_eq!(format!("{:?}", format), "HTML");
    }
}
