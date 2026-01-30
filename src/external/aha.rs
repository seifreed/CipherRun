// aha integration - ANSI to HTML converter
// Converts ANSI colored terminal output to HTML

use crate::Result;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// aha (ANSI HTML Adapter) wrapper
pub struct Aha {
    aha_path: String,
}

impl Default for Aha {
    fn default() -> Self {
        Self::new()
    }
}

impl Aha {
    pub fn new() -> Self {
        Self {
            aha_path: "aha".to_string(),
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { aha_path: path }
    }

    /// Check if aha is available
    pub fn is_available(&self) -> bool {
        Command::new(&self.aha_path)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Convert ANSI text to HTML
    pub fn convert(&self, ansi_text: &str) -> Result<String> {
        let mut child = Command::new(&self.aha_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Write ANSI text to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ansi_text.as_bytes())?;
        }

        // Wait for completion and get output
        let output = child.wait_with_output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(crate::error::TlsError::Other(format!(
                "aha conversion failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    /// Convert ANSI text to HTML with options
    pub fn convert_with_options(&self, ansi_text: &str, options: &AhaOptions) -> Result<String> {
        let mut cmd = Command::new(&self.aha_path);

        if options.no_header {
            cmd.arg("--no-header");
        }

        if options.black {
            cmd.arg("--black");
        }

        if let Some(ref title) = options.title {
            cmd.arg("--title");
            cmd.arg(title);
        }

        if let Some(ref stylesheet) = options.stylesheet {
            cmd.arg("--stylesheet");
            cmd.arg(stylesheet);
        }

        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Write ANSI text to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ansi_text.as_bytes())?;
        }

        // Wait for completion and get output
        let output = child.wait_with_output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(crate::error::TlsError::Other(format!(
                "aha conversion failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    /// Convert file to HTML
    pub fn convert_file(&self, input_path: &str, output_path: &str) -> Result<()> {
        // SECURITY: Validate paths to prevent command injection via path arguments
        // Check for null bytes and obvious shell metacharacters
        if input_path.contains('\0') || output_path.contains('\0') {
            return Err(crate::error::TlsError::Other(
                "Path contains null byte".to_string(),
            ));
        }

        // Verify paths don't contain shell metacharacters
        let dangerous = ['|', '&', ';', '$', '`', '\n', '\r'];
        for ch in dangerous.iter() {
            if input_path.contains(*ch) || output_path.contains(*ch) {
                return Err(crate::error::TlsError::Other(format!(
                    "Path contains dangerous character: '{}'",
                    ch
                )));
            }
        }

        // Verify paths exist or are creatable
        if !Path::new(input_path).exists() {
            return Err(crate::error::TlsError::Other(format!(
                "Input file does not exist: {}",
                input_path
            )));
        }

        let output = Command::new(&self.aha_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("--input")
            .arg(input_path)
            .arg("--output")
            .arg(output_path)
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            Err(crate::error::TlsError::Other(format!(
                "aha file conversion failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }
}

/// aha conversion options
#[derive(Debug, Clone, Default)]
pub struct AhaOptions {
    pub no_header: bool,
    pub black: bool,
    pub title: Option<String>,
    pub stylesheet: Option<String>,
}

/// Convert CipherRun colored output to HTML
pub fn convert_report_to_html(report: &str, title: Option<&str>) -> Result<String> {
    let aha = Aha::new();

    if !aha.is_available() {
        return Err(crate::error::TlsError::Other(
            "aha is not available in PATH".to_string(),
        ));
    }

    let options = AhaOptions {
        no_header: false,
        black: false,
        title: title.map(|t| t.to_string()),
        stylesheet: None,
    };

    aha.convert_with_options(report, &options)
}

/// Simple fallback converter (if aha is not available)
pub fn simple_ansi_to_html(ansi_text: &str) -> String {
    // This is a simple fallback that just removes ANSI codes
    // and wraps in basic HTML

    let mut html = String::from("<html><head><meta charset=\"UTF-8\"><style>");
    html.push_str("body { background-color: #000; color: #0f0; font-family: monospace; }");
    html.push_str("</style></head><body><pre>");

    // Remove ANSI escape codes
    let cleaned = strip_ansi_codes(ansi_text);
    html.push_str(&html_escape(&cleaned));

    html.push_str("</pre></body></html>");
    html
}

fn strip_ansi_codes(text: &str) -> String {
    // Simple regex-free ANSI code stripper
    let mut result = String::new();
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Skip ESC and everything until 'm'
            for next_ch in chars.by_ref() {
                if next_ch == 'm' {
                    break;
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_codes() {
        let ansi = "\x1b[31mRed text\x1b[0m Normal";
        let stripped = strip_ansi_codes(ansi);
        assert_eq!(stripped, "Red text Normal");
    }

    #[test]
    fn test_html_escape() {
        let text = "<script>alert('XSS')</script>";
        let escaped = html_escape(text);
        assert!(escaped.contains("&lt;"));
        assert!(escaped.contains("&gt;"));
    }

    #[test]
    fn test_simple_ansi_to_html() {
        let ansi = "\x1b[31mRed\x1b[0m";
        let html = simple_ansi_to_html(ansi);
        assert!(html.contains("<html>"));
        assert!(html.contains("Red"));
    }
}
