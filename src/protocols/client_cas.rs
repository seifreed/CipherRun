// Client CAs List - Extract acceptable CAs for client authentication

mod model;
mod parser;

pub use model::{ClientCA, ClientCAsResult};

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const MAX_CLIENT_CA_HANDSHAKE_BYTES: usize = 32 * 1024;

pub struct ClientCAsTester {
    target: Target,
    sni_hostname: Option<String>,
}

impl ClientCAsTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            sni_hostname: None,
        }
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    pub async fn enumerate_client_cas(&self) -> Result<ClientCAsResult> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let overall_read_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_secs(2);

        let mut stream =
            match crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await {
                Ok(stream) => stream,
                _ => {
                    return Ok(ClientCAsResult {
                        cas: Vec::new(),
                        requires_client_auth: false,
                        inconclusive: true,
                    });
                }
            };

        let mut builder =
            crate::protocols::handshake::ClientHelloBuilder::new(crate::protocols::Protocol::TLS12);
        builder.add_cipher(0xc030);

        let sni_hostname = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        );

        if let Ok(client_hello) = builder.build_with_defaults(sni_hostname.as_deref())
            && let Ok(response) = timeout(overall_read_timeout, async {
                stream.write_all(&client_hello).await?;
                self.read_tls_handshake_bytes(&mut stream, read_timeout)
                    .await
            })
            .await
            && let Ok(data) = response
        {
            let cert_request = match self.find_certificate_request(&data) {
                Ok(request) => request,
                Err(_) => {
                    return Ok(ClientCAsResult {
                        cas: Vec::new(),
                        requires_client_auth: false,
                        inconclusive: true,
                    });
                }
            };
            let cas = cert_request.clone().unwrap_or_default();

            let inconclusive = data.is_empty() || !Self::has_complete_tls_record(&data);

            return Ok(ClientCAsResult {
                requires_client_auth: cert_request.is_some(),
                cas,
                inconclusive,
            });
        }

        Ok(ClientCAsResult {
            cas: Vec::new(),
            requires_client_auth: false,
            inconclusive: true,
        })
    }

    fn has_complete_tls_record(data: &[u8]) -> bool {
        if data.len() < 5 || data.first() != Some(&0x16) {
            return false;
        }

        let Some(record_len) = data
            .get(3..5)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_be_bytes)
        else {
            return false;
        };
        let record_len = record_len as usize;
        data.len() >= 5 + record_len
    }

    async fn read_tls_handshake_bytes<S>(
        &self,
        stream: &mut S,
        read_timeout: Duration,
    ) -> Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let mut response = Vec::new();
        let mut chunk = vec![0u8; 4096];

        loop {
            match timeout(read_timeout, stream.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    let Some(read_bytes) = chunk.get(..n) else {
                        return Err(crate::TlsError::ParseError {
                            message: "TLS handshake read length exceeded buffer".to_string(),
                        });
                    };
                    if response
                        .len()
                        .checked_add(read_bytes.len())
                        .is_none_or(|len| len > MAX_CLIENT_CA_HANDSHAKE_BYTES)
                    {
                        return Err(crate::TlsError::ParseError {
                            message: "TLS handshake response exceeded maximum size".to_string(),
                        });
                    }
                    response.extend_from_slice(read_bytes);
                    if self
                        .find_certificate_request(&response)
                        .is_ok_and(|request| request.is_some())
                    {
                        break;
                    }
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => break,
            }
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dn(cn: &str, org: &str) -> Vec<u8> {
        let mut dn = Vec::new();

        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c]);
        dn.push(cn.len() as u8);
        dn.extend_from_slice(cn.as_bytes());

        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c]);
        dn.push(org.len() as u8);
        dn.extend_from_slice(org.as_bytes());

        dn
    }

    fn build_raw_dn(cn_bytes: &[u8], org_bytes: &[u8]) -> Vec<u8> {
        let mut dn = Vec::new();

        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c]);
        dn.push(cn_bytes.len() as u8);
        dn.extend_from_slice(cn_bytes);

        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c]);
        dn.push(org_bytes.len() as u8);
        dn.extend_from_slice(org_bytes);

        dn
    }

    fn push_der_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
    }

    fn build_raw_dn_der(cn_bytes: &[u8], org_bytes: &[u8]) -> Vec<u8> {
        let mut dn = Vec::new();

        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c]);
        push_der_len(&mut dn, cn_bytes.len());
        dn.extend_from_slice(cn_bytes);

        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c]);
        push_der_len(&mut dn, org_bytes.len());
        dn.extend_from_slice(org_bytes);

        dn
    }

    fn build_certificate_request(dn: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]);

        let ca_list_len = dn.len() as u16 + 2;
        body.extend_from_slice(&ca_list_len.to_be_bytes());
        body.extend_from_slice(&(dn.len() as u16).to_be_bytes());
        body.extend_from_slice(dn);

        let body_len = body.len() as u32;
        let mut handshake = vec![
            13,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);
        handshake
    }

    #[test]
    fn test_extract_dn_fields() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = build_dn("Example CN", "Example Org");
        let (cn, org) = tester
            .extract_dn_fields(&dn)
            .expect("DN fields should parse");
        assert_eq!(cn.as_deref(), Some("Example CN"));
        assert_eq!(org.as_deref(), Some("Example Org"));
    }

    #[test]
    fn test_extract_dn_fields_reads_der_long_form_lengths() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let cn = "A".repeat(130);
        let dn = build_raw_dn_der(cn.as_bytes(), b"Example Org");
        let (parsed_cn, parsed_org) = tester
            .extract_dn_fields(&dn)
            .expect("DN fields should parse");

        assert_eq!(parsed_cn.as_deref(), Some(cn.as_str()));
        assert_eq!(parsed_org.as_deref(), Some("Example Org"));
    }

    #[test]
    fn test_extract_dn_fields_reads_final_minimal_attribute() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let mut dn = vec![0x30];
        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c]);
        dn.push(1);
        dn.push(b'Z');

        let (_, org) = tester
            .extract_dn_fields(&dn)
            .expect("DN fields should parse");

        assert_eq!(org.as_deref(), Some("Z"));
    }

    #[test]
    fn test_parse_ca_list() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = build_dn("CN1", "ORG1");
        let handshake = build_certificate_request(&dn);

        let cas = tester
            .parse_ca_list(&handshake)
            .expect("test assertion should succeed");
        assert_eq!(cas.len(), 1);
        assert_eq!(cas[0].common_name.as_deref(), Some("CN1"));
        assert_eq!(cas[0].organization.as_deref(), Some("ORG1"));
    }

    #[test]
    fn test_extract_dn_fields_empty() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let (cn, org) = tester
            .extract_dn_fields(&[])
            .expect("empty DN should parse");
        assert!(cn.is_none());
        assert!(org.is_none());
    }

    #[test]
    fn test_extract_dn_fields_rejects_invalid_utf8() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = build_raw_dn(&[0xff], b"Example Org");
        let err = tester
            .extract_dn_fields(&dn)
            .expect_err("invalid DN UTF-8 should fail");
        assert!(
            err.to_string()
                .contains("Invalid certificate request DN UTF-8")
        );
    }

    #[test]
    fn test_extract_dn_fields_rejects_truncated_value() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x05, b'A'];
        let err = tester
            .extract_dn_fields(&dn)
            .expect_err("truncated DN value should fail");
        assert!(
            err.to_string()
                .contains("CertificateRequest DN value truncated")
        );
    }

    #[test]
    fn test_parse_certificate_request() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = build_dn("CN2", "ORG2");
        let handshake = build_certificate_request(&dn);

        let record_len = handshake.len() as u16;
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        let cas = tester.parse_certificate_request(&record);
        assert_eq!(cas.len(), 1);
        assert_eq!(cas[0].common_name.as_deref(), Some("CN2"));
    }

    #[test]
    fn test_parse_certificate_request_after_other_handshake_messages() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = build_dn("CN3", "ORG3");

        let server_hello = vec![2, 0, 0, 0];
        let cert_request = build_certificate_request(&dn);

        let first_record_len = server_hello.len() as u16;
        let mut first_record = vec![0x16, 0x03, 0x03];
        first_record.extend_from_slice(&first_record_len.to_be_bytes());
        first_record.extend_from_slice(&server_hello);

        let second_record_len = cert_request.len() as u16;
        let mut second_record = vec![0x16, 0x03, 0x03];
        second_record.extend_from_slice(&second_record_len.to_be_bytes());
        second_record.extend_from_slice(&cert_request);

        let mut combined = first_record;
        combined.extend_from_slice(&second_record);

        let cas = tester.parse_certificate_request(&combined);
        assert_eq!(cas.len(), 1);
        assert_eq!(cas[0].common_name.as_deref(), Some("CN3"));
        assert_eq!(cas[0].organization.as_deref(), Some("ORG3"));
    }

    #[test]
    fn test_parse_ca_list_too_short() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let err = tester
            .parse_ca_list(&[13, 0, 0, 0])
            .expect_err("short CertificateRequest should fail");
        assert!(err.to_string().contains("CertificateRequest too short"));
    }

    #[test]
    fn test_parse_ca_list_rejects_oversized_certificate_types_length() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let malformed = vec![
            13, 0, 0, 6, // CertificateRequest handshake header
            6, // certificate_types length claims six bytes
            0, // only one certificate type byte is present
            0, 0, // signature algorithms length
            0, 0, // padding to satisfy the minimum length check
        ];

        let err = tester
            .parse_ca_list(&malformed)
            .expect_err("oversized certificate_types length should fail");
        assert!(
            err.to_string()
                .contains("CertificateRequest certificate types length exceeds message")
        );
    }

    #[test]
    fn test_parse_ca_list_rejects_trailing_bytes_in_ca_list() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = build_dn("CN4", "ORG4");
        let mut body = Vec::new();
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]);
        let ca_list_len = (dn.len() + 3) as u16;
        body.extend_from_slice(&ca_list_len.to_be_bytes());
        body.extend_from_slice(&(dn.len() as u16).to_be_bytes());
        body.extend_from_slice(&dn);
        body.push(0xff);

        let body_len = body.len() as u32;
        let mut handshake = vec![
            13,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let err = tester
            .parse_ca_list(&handshake)
            .expect_err("trailing bytes in CA list should fail");
        assert!(
            err.to_string()
                .contains("CertificateRequest CA list contains trailing bytes")
        );
    }

    #[test]
    fn test_parse_ca_list_rejects_trailing_bytes_after_ca_list() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let dn = build_dn("CN5", "ORG5");
        let mut handshake = build_certificate_request(&dn);
        handshake.push(0xff);
        let body_len = handshake.len() - 4;
        handshake[1] = ((body_len >> 16) & 0xff) as u8;
        handshake[2] = ((body_len >> 8) & 0xff) as u8;
        handshake[3] = (body_len & 0xff) as u8;

        let err = tester
            .parse_ca_list(&handshake)
            .expect_err("trailing bytes after CA list should fail");
        assert!(
            err.to_string()
                .contains("CertificateRequest contains trailing bytes after CA list")
        );
    }

    #[test]
    fn test_parse_certificate_request_skips_non_handshake() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let record = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
        let cas = tester.parse_certificate_request(&record);
        assert!(cas.is_empty());
    }

    #[test]
    fn test_find_certificate_request_rejects_truncated_non_handshake_record() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let record = vec![0x15, 0x03, 0x03, 0x00, 0x20, 0x01];
        let err = tester
            .find_certificate_request(&record)
            .expect_err("truncated non-handshake record should fail");
        assert!(
            err.to_string()
                .contains("TLS record length exceeds available data")
        );
    }

    #[test]
    fn test_find_certificate_request_rejects_truncated_record_header() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let record = vec![0x16, 0x03, 0x03, 0x00];
        let err = tester
            .find_certificate_request(&record)
            .expect_err("truncated TLS record header should fail");
        assert!(err.to_string().contains("TLS record header truncated"));
    }

    #[test]
    fn test_find_certificate_request_rejects_truncated_handshake_header() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let record = vec![0x16, 0x03, 0x03, 0x00, 0x03, 13, 0, 0];
        let err = tester
            .find_certificate_request(&record)
            .expect_err("truncated handshake header should fail");
        assert!(
            err.to_string()
                .contains("Handshake message header truncated")
        );
    }

    #[test]
    fn test_parse_ca_list_empty_returns_none() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let err = tester
            .parse_ca_list(&[])
            .expect_err("empty CertificateRequest should fail");
        assert!(err.to_string().contains("CertificateRequest too short"));
    }

    #[test]
    fn test_find_certificate_request_rejects_malformed_ca_list() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let malformed = vec![13, 0, 0, 6, 1, 1, 0, 0, 4, 0];
        let record_len = malformed.len() as u16;
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&malformed);

        let err = tester
            .find_certificate_request(&record)
            .expect_err("malformed CertificateRequest should fail");
        assert!(err.to_string().contains("CA list length exceeds message"));
    }

    #[test]
    fn test_find_certificate_request_rejects_truncated_ca_entry() {
        let tester = ClientCAsTester::new(
            Target::with_ips(
                "example.test".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid IP")],
            )
            .expect("test assertion should succeed"),
        );

        let handshake = vec![
            13, 0, 0, 11, // CertificateRequest handshake header
            1, 1, // certificate_types length + type
            0, 2, 0x04, 0x01, // signature algorithms length + one algorithm
            0, 3, // CA list length
            0, 2, 0x30, // truncated CA distinguished name (claims 2 bytes, provides 1)
        ];
        let record_len = handshake.len() as u16;
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        let err = tester
            .find_certificate_request(&record)
            .expect_err("truncated CA entry should fail");
        assert!(
            err.to_string()
                .contains("distinguished name length exceeds list")
        );
    }

    #[tokio::test]
    async fn test_enumerate_client_cas_closed_target_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        drop(listener);

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = ClientCAsTester::new(target);

        let result = tester
            .enumerate_client_cas()
            .await
            .expect("client CA probe should return result");

        assert!(result.inconclusive);
        assert!(!result.requires_client_auth);
        assert!(result.cas.is_empty());
    }

    #[tokio::test]
    async fn test_enumerate_client_cas_truncated_response_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket
                    .write_all(&[0x16, 0x03, 0x03, 0x00, 0x20, 0x02])
                    .await;
            }
        });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = ClientCAsTester::new(target);

        let result = tester
            .enumerate_client_cas()
            .await
            .expect("client CA probe should return result");

        assert!(result.inconclusive);
        assert!(!result.requires_client_auth);
    }

    #[tokio::test]
    async fn test_read_tls_handshake_bytes_rejects_oversized_response() {
        let (mut client, mut server) = tokio::io::duplex(MAX_CLIENT_CA_HANDSHAKE_BYTES + 16);
        tokio::spawn(async move {
            let _ = server
                .write_all(&vec![0x16; MAX_CLIENT_CA_HANDSHAKE_BYTES + 1])
                .await;
        });

        let tester = ClientCAsTester::new(
            Target::with_ips(
                "localhost".to_string(),
                443,
                vec!["127.0.0.1".parse().expect("valid loopback")],
            )
            .expect("target should build"),
        );
        let err = tester
            .read_tls_handshake_bytes(&mut client, Duration::from_secs(1))
            .await
            .expect_err("oversized response must fail");

        assert!(err.to_string().contains("exceeded maximum size"));
    }
}
