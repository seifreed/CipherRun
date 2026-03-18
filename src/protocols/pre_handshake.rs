// Pre-handshake façade.

#[path = "pre_handshake/client_hello.rs"]
mod client_hello;
#[path = "pre_handshake/parser.rs"]
mod parser;

use crate::Result;
use crate::certificates::parser::CertificateInfo;
use crate::error::TlsError;
use crate::utils::network::Target;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Pre-handshake scanner for fast certificate retrieval
pub struct PreHandshakeScanner {
    target: Target,
    timeout_duration: Duration,
}

impl PreHandshakeScanner {
    /// Create new pre-handshake scanner
    pub fn new(target: Target) -> Self {
        Self {
            target,
            timeout_duration: Duration::from_secs(10),
        }
    }

    /// Set custom timeout
    pub fn with_timeout(mut self, timeout_duration: Duration) -> Self {
        self.timeout_duration = timeout_duration;
        self
    }

    /// Perform pre-handshake scan - early termination after ServerHello
    pub async fn scan_pre_handshake(&self) -> Result<PreHandshakeScanResult> {
        let start_time = Instant::now();

        let addr = format!("{}:{}", self.target.hostname, self.target.port);
        let mut stream = timeout(self.timeout_duration, TcpStream::connect(&addr))
            .await
            .map_err(|_| TlsError::Timeout {
                duration: self.timeout_duration,
            })?
            .map_err(|e| TlsError::IoError { source: e })?;

        let client_hello = self.build_client_hello()?;
        stream
            .write_all(&client_hello)
            .await
            .map_err(|e| TlsError::IoError { source: e })?;

        let mut response_buffer = vec![0u8; 16384];
        let bytes_read = timeout(self.timeout_duration, stream.read(&mut response_buffer))
            .await
            .map_err(|_| TlsError::Timeout {
                duration: self.timeout_duration,
            })?
            .map_err(|e| TlsError::IoError { source: e })?;

        if bytes_read == 0 {
            return Err(TlsError::ConnectionClosed {
                details: "Server closed connection before sending ServerHello".to_string(),
            });
        }

        let response_data = &response_buffer[..bytes_read];
        let parse_result = self.parse_handshake_response(response_data)?;

        drop(stream);
        let elapsed = start_time.elapsed();

        Ok(PreHandshakeScanResult {
            success: true,
            certificate_data: parse_result.certificate_data,
            server_hello_data: parse_result.server_hello_data,
            handshake_time_ms: elapsed.as_millis() as u64,
            protocol_version: parse_result.protocol_version,
            cipher_suite: parse_result.cipher_suite,
            compression_method: parse_result.compression_method,
        })
    }
}

/// Result of pre-handshake scan
#[derive(Debug, Clone)]
pub struct PreHandshakeScanResult {
    pub success: bool,
    pub certificate_data: Option<CertificateInfo>,
    pub server_hello_data: Option<Vec<u8>>,
    pub handshake_time_ms: u64,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub compression_method: Option<u8>,
}

/// Internal struct for parsing handshake
struct HandshakeParseResult {
    certificate_data: Option<CertificateInfo>,
    server_hello_data: Option<Vec<u8>>,
    protocol_version: Option<String>,
    cipher_suite: Option<String>,
    compression_method: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    fn u24_len(len: usize) -> [u8; 3] {
        [
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]
    }

    fn build_handshake_message(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(4 + body.len());
        message.push(handshake_type);
        message.extend_from_slice(&u24_len(body.len()));
        message.extend_from_slice(body);
        message
    }

    fn build_handshake_record(messages: &[Vec<u8>]) -> Vec<u8> {
        let body_len: usize = messages.iter().map(Vec::len).sum();
        let mut record = Vec::with_capacity(5 + body_len);
        record.push(0x16);
        record.push(0x03);
        record.push(0x03);
        record.extend_from_slice(&(body_len as u16).to_be_bytes());
        for message in messages {
            record.extend_from_slice(message);
        }
        record
    }

    fn build_server_hello_body(cipher_suite: u16, compression: u8) -> Vec<u8> {
        let mut body = vec![0u8; 38];
        body[0] = 0x03;
        body[1] = 0x03;
        for byte in body[2..34].iter_mut() {
            *byte = 0x11;
        }
        body[34] = (cipher_suite >> 8) as u8;
        body[35] = (cipher_suite & 0xff) as u8;
        body[36] = compression;
        body
    }

    #[test]
    fn test_build_server_hello_body_length() {
        let body = build_server_hello_body(0x1301, 0x00);
        assert_eq!(body.len(), 38);
        assert_eq!(body[34], 0x13);
        assert_eq!(body[35], 0x01);
    }

    #[test]
    fn test_client_hello_build() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let client_hello = scanner
            .build_client_hello()
            .expect("test assertion should succeed");

        assert_eq!(client_hello[0], 0x16);
        assert_eq!(client_hello[1], 0x03);
        assert_eq!(client_hello[2], 0x01);
        assert_eq!(client_hello[5], 0x01);
    }

    #[test]
    fn test_client_hello_lengths_match() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let client_hello = scanner
            .build_client_hello()
            .expect("test assertion should succeed");

        let record_len = u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize;
        let handshake_len =
            u32::from_be_bytes([0, client_hello[6], client_hello[7], client_hello[8]]) as usize;

        assert_eq!(record_len, client_hello.len() - 5);
        assert_eq!(handshake_len, client_hello.len() - 9);
    }

    #[test]
    fn test_sni_extension() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let sni = scanner.build_sni_extension();

        assert_eq!(sni[0], 0x00);
        assert_eq!(sni[1], 0x00);
        assert!(sni.len() > 4);
    }

    #[test]
    fn test_parse_handshake_response_server_hello_only() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let server_hello_body = build_server_hello_body(0x1301, 0x00);
        let server_hello = build_handshake_message(0x02, &server_hello_body);
        let record = build_handshake_record(&[server_hello]);

        let parsed = scanner
            .parse_handshake_response(&record)
            .expect("test assertion should succeed");

        assert_eq!(parsed.protocol_version, Some("1.3".to_string()));
        assert_eq!(parsed.cipher_suite, Some("0x1301".to_string()));
        assert_eq!(parsed.compression_method, Some(0x00));
        assert!(parsed.server_hello_data.is_some());
        assert!(parsed.certificate_data.is_none());
    }

    #[test]
    fn test_parse_handshake_response_with_certificate() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);

        let mut params =
            CertificateParams::new(vec!["example.com".to_string()]).expect("params should build");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "example.com");
        params.distinguished_name = dn;
        let key_pair = KeyPair::generate().expect("key pair should generate");
        let cert = params.self_signed(&key_pair).expect("cert should build");
        let cert_der = cert.der().as_ref().to_vec();

        let server_hello_body = build_server_hello_body(0xc02f, 0x00);
        let server_hello = build_handshake_message(0x02, &server_hello_body);

        let mut cert_body = Vec::new();
        let certs_len = cert_der.len() + 3;
        cert_body.extend_from_slice(&u24_len(certs_len));
        cert_body.extend_from_slice(&u24_len(cert_der.len()));
        cert_body.extend_from_slice(&cert_der);
        let certificate = build_handshake_message(0x0b, &cert_body);

        let record = build_handshake_record(&[server_hello, certificate]);

        let parsed = scanner
            .parse_handshake_response(&record)
            .expect("test assertion should succeed");

        let cert_info = parsed
            .certificate_data
            .expect("certificate should be parsed");
        assert!(cert_info.subject.contains("CN=example.com"));
        assert!(cert_info.san.iter().any(|name| name == "example.com"));
        assert!(parsed.server_hello_data.is_some());
    }

    #[test]
    fn test_parse_handshake_response_skips_non_handshake_records() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let mut record = Vec::new();
        record.push(0x15);
        record.push(0x03);
        record.push(0x03);
        record.extend_from_slice(&1u16.to_be_bytes());
        record.push(0x00);

        let parsed = scanner
            .parse_handshake_response(&record)
            .expect("test assertion should succeed");
        assert!(parsed.certificate_data.is_none());
        assert!(parsed.server_hello_data.is_none());
    }

    #[test]
    fn test_parse_handshake_response_truncated_record_header() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let data = vec![0x16, 0x03, 0x03, 0x00];
        let parsed = scanner
            .parse_handshake_response(&data)
            .expect("test assertion should succeed");
        assert!(parsed.server_hello_data.is_none());
        assert!(parsed.certificate_data.is_none());
    }

    #[test]
    fn test_parse_handshake_response_record_length_exceeds_buffer() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let mut record = Vec::new();
        record.push(0x16);
        record.push(0x03);
        record.push(0x03);
        record.extend_from_slice(&10u16.to_be_bytes());
        record.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        let parsed = scanner
            .parse_handshake_response(&record)
            .expect("test assertion should succeed");
        assert!(parsed.server_hello_data.is_none());
        assert!(parsed.certificate_data.is_none());
    }

    #[test]
    fn test_parse_handshake_response_truncated_handshake_message() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let mut message = Vec::new();
        message.push(0x02);
        message.extend_from_slice(&u24_len(10));
        message.extend_from_slice(&[0x03, 0x03]);
        let record = build_handshake_record(&[message]);

        let parsed = scanner
            .parse_handshake_response(&record)
            .expect("test assertion should succeed");
        assert!(parsed.server_hello_data.is_none());
        assert!(parsed.certificate_data.is_none());
    }

    #[test]
    fn test_parse_handshake_response_certificate_length_exceeds() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let scanner = PreHandshakeScanner::new(target);
        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&u24_len(6));
        cert_body.extend_from_slice(&u24_len(16));
        let certificate = build_handshake_message(0x0b, &cert_body);
        let record = build_handshake_record(&[certificate]);

        let parsed = scanner
            .parse_handshake_response(&record)
            .expect("test assertion should succeed");
        assert!(parsed.certificate_data.is_none());
    }
}
