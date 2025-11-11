// xxd integration - Hex dump utility
// Create hexdumps for debugging TLS packets

use crate::Result;
use std::io::Write;
use std::process::{Command, Stdio};

/// xxd wrapper
pub struct Xxd {
    xxd_path: String,
}

impl Default for Xxd {
    fn default() -> Self {
        Self::new()
    }
}

impl Xxd {
    pub fn new() -> Self {
        Self {
            xxd_path: "xxd".to_string(),
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { xxd_path: path }
    }

    /// Check if xxd is available
    pub fn is_available(&self) -> bool {
        Command::new(&self.xxd_path)
            .arg("-version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Create hex dump from binary data
    pub fn dump(&self, data: &[u8]) -> Result<String> {
        let mut child = Command::new(&self.xxd_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Write binary data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data)?;
        }

        // Wait for completion and get output
        let output = child.wait_with_output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(crate::error::TlsError::Other(format!(
                "xxd failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    /// Create hex dump with options
    pub fn dump_with_options(&self, data: &[u8], options: &XxdOptions) -> Result<String> {
        let mut cmd = Command::new(&self.xxd_path);

        if let Some(cols) = options.cols {
            cmd.arg("-c");
            cmd.arg(cols.to_string());
        }

        if let Some(len) = options.len {
            cmd.arg("-l");
            cmd.arg(len.to_string());
        }

        if options.plain {
            cmd.arg("-p");
        }

        if options.uppercase {
            cmd.arg("-u");
        }

        if options.bits {
            cmd.arg("-b");
        }

        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Write binary data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data)?;
        }

        // Wait for completion and get output
        let output = child.wait_with_output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(crate::error::TlsError::Other(format!(
                "xxd failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    /// Reverse hex dump back to binary
    pub fn reverse(&self, hexdump: &str) -> Result<Vec<u8>> {
        let mut child = Command::new(&self.xxd_path)
            .arg("-r")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Write hexdump to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(hexdump.as_bytes())?;
        }

        // Wait for completion and get output
        let output = child.wait_with_output()?;

        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(crate::error::TlsError::Other(format!(
                "xxd reverse failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    /// Dump file to hex
    pub fn dump_file(&self, path: &str) -> Result<String> {
        let output = Command::new(&self.xxd_path).arg(path).output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(crate::error::TlsError::Other(format!(
                "xxd file dump failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }
}

/// xxd options
#[derive(Debug, Clone, Default)]
pub struct XxdOptions {
    pub cols: Option<usize>, // -c: number of octets per line
    pub len: Option<usize>,  // -l: stop after <len> octets
    pub plain: bool,         // -p: plain hexdump style
    pub uppercase: bool,     // -u: use uppercase hex
    pub bits: bool,          // -b: binary digit dump
}

/// Format TLS packet as hex dump for debugging
pub fn format_tls_packet(packet: &[u8], name: &str) -> Result<String> {
    let xxd = Xxd::new();

    let mut output = format!("=== {} ({} bytes) ===\n", name, packet.len());

    if xxd.is_available() {
        let options = XxdOptions {
            cols: Some(16),
            ..Default::default()
        };

        output.push_str(&xxd.dump_with_options(packet, &options)?);
    } else {
        // Fallback to simple hex dump
        output.push_str(&simple_hex_dump(packet, 16));
    }

    Ok(output)
}

/// Simple hex dump implementation (fallback if xxd is not available)
pub fn simple_hex_dump(data: &[u8], cols: usize) -> String {
    let mut output = String::new();

    for (i, chunk) in data.chunks(cols).enumerate() {
        // Offset
        output.push_str(&format!("{:08x}: ", i * cols));

        // Hex values
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x}", byte));
            if j % 2 == 1 {
                output.push(' ');
            }
        }

        // Padding
        let padding = (cols - chunk.len()) * 2 + (cols - chunk.len()) / 2;
        for _ in 0..padding {
            output.push(' ');
        }

        output.push(' ');

        // ASCII representation
        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }

        output.push('\n');
    }

    output
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.replace([' ', '\n'], "");

    if hex.len() % 2 != 0 {
        return Err(crate::error::TlsError::ParseError {
            message: "Hex string must have even length".to_string(),
        });
    }

    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte =
            u8::from_str_radix(byte_str, 16).map_err(|e| crate::error::TlsError::ParseError {
                message: format!("Invalid hex: {}", e),
            })?;
        bytes.push(byte);
    }

    Ok(bytes)
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8], uppercase: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if uppercase {
                format!("{:02X}", b)
            } else {
                format!("{:02x}", b)
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hex_dump() {
        let data = b"Hello, World!";
        let dump = simple_hex_dump(data, 16);
        assert!(dump.contains("4865")); // "He" in hex
        assert!(dump.contains("6c6c")); // "ll" in hex
        assert!(dump.contains("Hello")); // ASCII representation
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "48656c6c6f";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = b"Hello";
        let hex_lower = bytes_to_hex(bytes, false);
        assert_eq!(hex_lower, "48656c6c6f");

        let hex_upper = bytes_to_hex(bytes, true);
        assert_eq!(hex_upper, "48656C6C6F");
    }

    #[test]
    fn test_hex_to_bytes_with_spaces() {
        let hex = "48 65 6c 6c 6f";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        let hex = "xyz";
        assert!(hex_to_bytes(hex).is_err());

        let hex = "123"; // Odd length
        assert!(hex_to_bytes(hex).is_err());
    }
}
