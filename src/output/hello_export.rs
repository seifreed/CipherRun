// Raw Client/Server Hello export rendering
//
// Serializes captured TLS Hello bytes (see fingerprint::ClientHelloCapture /
// ServerHelloCapture) into the format requested by `--export-hello`.

use crate::external::xxd::{bytes_to_hex, simple_hex_dump};
use crate::{Result, TlsError};
use base64::Engine;

/// Bytes per row used by the hexdump rendering.
const HEXDUMP_COLUMNS: usize = 16;

/// Output encoding for an exported Hello message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloExportFormat {
    /// Continuous lowercase hex string.
    Hex,
    /// Standard base64.
    Base64,
    /// Offset/hex/ASCII hexdump (human readable).
    Hexdump,
    /// Raw bytes, unchanged.
    Binary,
}

impl HelloExportFormat {
    /// Parse the `--export-hello` value. Accepts `hex`, `base64`, `hexdump`, and
    /// `binary` (case-insensitive).
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_lowercase().as_str() {
            "hex" => Ok(Self::Hex),
            "base64" => Ok(Self::Base64),
            "hexdump" => Ok(Self::Hexdump),
            "binary" => Ok(Self::Binary),
            other => Err(TlsError::InvalidInput {
                message: format!(
                    "Unknown --export-hello format '{}': expected hex, base64, hexdump, or binary",
                    other
                ),
            }),
        }
    }

    /// File extension to use when writing an exported Hello in this format.
    pub fn file_extension(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Base64 => "b64",
            Self::Hexdump => "hexdump.txt",
            Self::Binary => "bin",
        }
    }
}

/// Render raw Hello bytes into the requested export format.
pub fn render_hello(bytes: &[u8], format: HelloExportFormat) -> Vec<u8> {
    match format {
        HelloExportFormat::Hex => bytes_to_hex(bytes, false).into_bytes(),
        HelloExportFormat::Base64 => base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .into_bytes(),
        HelloExportFormat::Hexdump => simple_hex_dump(bytes, HEXDUMP_COLUMNS).into_bytes(),
        HelloExportFormat::Binary => bytes.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accepts_known_formats_case_insensitive() {
        assert_eq!(
            HelloExportFormat::parse("HEX").expect("hex"),
            HelloExportFormat::Hex
        );
        assert_eq!(
            HelloExportFormat::parse("Base64").expect("base64"),
            HelloExportFormat::Base64
        );
        assert_eq!(
            HelloExportFormat::parse(" hexdump ").expect("hexdump"),
            HelloExportFormat::Hexdump
        );
        assert_eq!(
            HelloExportFormat::parse("binary").expect("binary"),
            HelloExportFormat::Binary
        );
    }

    #[test]
    fn test_parse_rejects_unknown_format() {
        assert!(HelloExportFormat::parse("pem").is_err());
    }

    #[test]
    fn test_render_hex_and_base64_and_binary() {
        let bytes = [0x16, 0x03, 0x01, 0xff];
        assert_eq!(render_hello(&bytes, HelloExportFormat::Hex), b"160301ff");
        assert_eq!(
            render_hello(&bytes, HelloExportFormat::Base64),
            base64::engine::general_purpose::STANDARD
                .encode(bytes)
                .into_bytes()
        );
        assert_eq!(render_hello(&bytes, HelloExportFormat::Binary), bytes);
    }
}
