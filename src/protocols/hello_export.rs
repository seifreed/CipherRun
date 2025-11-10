// Client/Server Hello Raw Data Export Module
// Exports raw handshake data in various formats for analysis

use serde::{Deserialize, Serialize};

/// Hello exporter for raw handshake data
pub struct HelloExporter;

impl HelloExporter {
    /// Export ClientHello to specified format
    pub fn export_client_hello(hello: &[u8], format: ExportFormat) -> String {
        Self::export_bytes(hello, format)
    }

    /// Export ServerHello to specified format
    pub fn export_server_hello(hello: &[u8], format: ExportFormat) -> String {
        Self::export_bytes(hello, format)
    }

    /// Export bytes in specified format
    fn export_bytes(data: &[u8], format: ExportFormat) -> String {
        match format {
            ExportFormat::Hex => hex::encode(data),
            ExportFormat::Base64 => base64::encode(data),
            ExportFormat::HexDump => Self::hex_dump(data),
            ExportFormat::Binary => {
                // Return as-is (for writing to file)
                String::from_utf8_lossy(data).to_string()
            }
        }
    }

    /// Create hex dump format (xxd-style)
    fn hex_dump(data: &[u8]) -> String {
        let mut output = String::new();
        let mut offset = 0;

        while offset < data.len() {
            // Address
            output.push_str(&format!("{:08x}: ", offset));

            // Hex bytes (16 per line)
            let end = (offset + 16).min(data.len());
            for i in offset..end {
                output.push_str(&format!("{:02x} ", data[i]));
                if i == offset + 7 {
                    output.push(' '); // Extra space at midpoint
                }
            }

            // Padding for incomplete lines
            let padding = 16 - (end - offset);
            for _ in 0..padding {
                output.push_str("   ");
            }
            if padding > 8 {
                output.push(' ');
            }

            // ASCII representation
            output.push_str(" |");
            for i in offset..end {
                let c = data[i];
                if (32..=126).contains(&c) {
                    output.push(c as char);
                } else {
                    output.push('.');
                }
            }
            output.push_str("|\n");

            offset = end;
        }

        output
    }

    /// Export both ClientHello and ServerHello together
    pub fn export_handshake(
        client_hello: &[u8],
        server_hello: &[u8],
        format: ExportFormat,
    ) -> HandshakeExport {
        HandshakeExport {
            client_hello: ClientHelloExport {
                hex: hex::encode(client_hello),
                base64: base64::encode(client_hello),
                length: client_hello.len(),
                format: format.clone(),
            },
            server_hello: ServerHelloExport {
                hex: hex::encode(server_hello),
                base64: base64::encode(server_hello),
                length: server_hello.len(),
                format: format.clone(),
            },
        }
    }

    /// Parse TLS record type from bytes
    pub fn identify_record_type(data: &[u8]) -> Option<TlsRecordType> {
        if data.is_empty() {
            return None;
        }

        match data[0] {
            0x14 => Some(TlsRecordType::ChangeCipherSpec),
            0x15 => Some(TlsRecordType::Alert),
            0x16 => Some(TlsRecordType::Handshake),
            0x17 => Some(TlsRecordType::ApplicationData),
            _ => Some(TlsRecordType::Unknown(data[0])),
        }
    }

    /// Parse handshake message type
    pub fn identify_handshake_type(data: &[u8]) -> Option<HandshakeType> {
        if data.len() < 6 {
            return None;
        }

        // Skip TLS record header (5 bytes) to get to handshake type
        match data[5] {
            0x00 => Some(HandshakeType::HelloRequest),
            0x01 => Some(HandshakeType::ClientHello),
            0x02 => Some(HandshakeType::ServerHello),
            0x0b => Some(HandshakeType::Certificate),
            0x0c => Some(HandshakeType::ServerKeyExchange),
            0x0d => Some(HandshakeType::CertificateRequest),
            0x0e => Some(HandshakeType::ServerHelloDone),
            0x0f => Some(HandshakeType::CertificateVerify),
            0x10 => Some(HandshakeType::ClientKeyExchange),
            0x14 => Some(HandshakeType::Finished),
            _ => Some(HandshakeType::Unknown(data[5])),
        }
    }

    /// Extract TLS version from record
    pub fn extract_tls_version(data: &[u8]) -> Option<(u8, u8)> {
        if data.len() < 3 {
            return None;
        }

        Some((data[1], data[2]))
    }

    /// Get human-readable version string
    pub fn version_string(major: u8, minor: u8) -> String {
        match (major, minor) {
            (3, 0) => "SSL 3.0".to_string(),
            (3, 1) => "TLS 1.0".to_string(),
            (3, 2) => "TLS 1.1".to_string(),
            (3, 3) => "TLS 1.2".to_string(),
            (3, 4) => "TLS 1.3".to_string(),
            _ => format!("Unknown ({}.{})", major, minor),
        }
    }
}

/// Export format options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    /// Hexadecimal encoding
    Hex,
    /// Base64 encoding
    Base64,
    /// Hex dump (xxd-style)
    HexDump,
    /// Raw binary (for file output)
    Binary,
}

/// Complete handshake export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeExport {
    pub client_hello: ClientHelloExport,
    pub server_hello: ServerHelloExport,
}

/// ClientHello export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHelloExport {
    pub hex: String,
    pub base64: String,
    pub length: usize,
    pub format: ExportFormat,
}

/// ServerHello export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHelloExport {
    pub hex: String,
    pub base64: String,
    pub length: usize,
    pub format: ExportFormat,
}

/// TLS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRecordType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

impl std::fmt::Display for TlsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsRecordType::ChangeCipherSpec => write!(f, "ChangeCipherSpec"),
            TlsRecordType::Alert => write!(f, "Alert"),
            TlsRecordType::Handshake => write!(f, "Handshake"),
            TlsRecordType::ApplicationData => write!(f, "ApplicationData"),
            TlsRecordType::Unknown(val) => write!(f, "Unknown(0x{:02x})", val),
        }
    }
}

/// Handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    Unknown(u8),
}

impl std::fmt::Display for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeType::HelloRequest => write!(f, "HelloRequest"),
            HandshakeType::ClientHello => write!(f, "ClientHello"),
            HandshakeType::ServerHello => write!(f, "ServerHello"),
            HandshakeType::Certificate => write!(f, "Certificate"),
            HandshakeType::ServerKeyExchange => write!(f, "ServerKeyExchange"),
            HandshakeType::CertificateRequest => write!(f, "CertificateRequest"),
            HandshakeType::ServerHelloDone => write!(f, "ServerHelloDone"),
            HandshakeType::CertificateVerify => write!(f, "CertificateVerify"),
            HandshakeType::ClientKeyExchange => write!(f, "ClientKeyExchange"),
            HandshakeType::Finished => write!(f, "Finished"),
            HandshakeType::Unknown(val) => write!(f, "Unknown(0x{:02x})", val),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_hex() {
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05];
        let hex = HelloExporter::export_client_hello(&data, ExportFormat::Hex);
        assert_eq!(hex, "1603010005");
    }

    #[test]
    fn test_export_base64() {
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05];
        let base64 = HelloExporter::export_client_hello(&data, ExportFormat::Base64);
        assert!(base64.len() > 0);
    }

    #[test]
    fn test_hex_dump() {
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03];
        let dump = HelloExporter::export_client_hello(&data, ExportFormat::HexDump);
        assert!(dump.contains("00000000:"));
        assert!(dump.contains("16 03 01"));
    }

    #[test]
    fn test_identify_record_type() {
        let handshake = vec![0x16, 0x03, 0x01];
        assert_eq!(
            HelloExporter::identify_record_type(&handshake),
            Some(TlsRecordType::Handshake)
        );

        let alert = vec![0x15, 0x03, 0x01];
        assert_eq!(
            HelloExporter::identify_record_type(&alert),
            Some(TlsRecordType::Alert)
        );
    }

    #[test]
    fn test_extract_tls_version() {
        let data = vec![0x16, 0x03, 0x03]; // TLS 1.2
        let version = HelloExporter::extract_tls_version(&data);
        assert_eq!(version, Some((3, 3)));

        let version_str = HelloExporter::version_string(3, 3);
        assert_eq!(version_str, "TLS 1.2");
    }

    #[test]
    fn test_version_strings() {
        assert_eq!(HelloExporter::version_string(3, 0), "SSL 3.0");
        assert_eq!(HelloExporter::version_string(3, 1), "TLS 1.0");
        assert_eq!(HelloExporter::version_string(3, 2), "TLS 1.1");
        assert_eq!(HelloExporter::version_string(3, 3), "TLS 1.2");
        assert_eq!(HelloExporter::version_string(3, 4), "TLS 1.3");
    }

    #[test]
    fn test_export_handshake() {
        let client = vec![0x16, 0x03, 0x01, 0x00, 0x05];
        let server = vec![0x16, 0x03, 0x03, 0x00, 0x39];

        let export = HelloExporter::export_handshake(&client, &server, ExportFormat::Hex);

        assert_eq!(export.client_hello.length, 5);
        assert_eq!(export.server_hello.length, 5);
        assert!(!export.client_hello.hex.is_empty());
        assert!(!export.server_hello.hex.is_empty());
    }
}
