// TLS Fallback SCSV (Signaling Cipher Suite Value) Testing
// RFC 7507 - TLS_FALLBACK_SCSV prevents protocol downgrade attacks
// Protects against attacks like POODLE by preventing fallback to older protocols

mod client_hello;
mod model;
mod network;
mod orchestration;

pub use model::FallbackScsvTestResult;

use crate::Result;
use crate::protocols::tester::ProtocolTester;
use crate::utils::network::Target;

/// TLS Fallback SCSV tester
pub struct FallbackScsvTester<'a> {
    target: &'a Target,
    sni_hostname: Option<String>,
    max_supported_protocol: Option<crate::protocols::Protocol>,
    test_all_ips: bool,
}

impl<'a> FallbackScsvTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            sni_hostname: None,
            max_supported_protocol: None,
            test_all_ips: false,
        }
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    pub async fn test(&mut self) -> Result<FallbackScsvTestResult> {
        tracing::debug!("Detecting maximum supported protocol version for SCSV testing");
        let protocol_tester =
            ProtocolTester::new(self.target.clone()).with_sni(self.sni_hostname.clone());

        match protocol_tester.get_preferred_protocol().await? {
            Some(max_protocol) => {
                self.max_supported_protocol = Some(max_protocol);
                tracing::debug!(
                    "Maximum supported protocol detected: {}",
                    max_protocol.name()
                );
            }
            None => {
                tracing::warn!(
                    "Could not detect any supported protocol - server may be unreachable"
                );
                return Ok(FallbackScsvTestResult {
                    supported: false,
                    accepts_downgrade: false,
                    vulnerable: false,
                    inconclusive: true,
                    not_applicable: false,
                    details: "Unable to detect supported protocols - server may be unreachable"
                        .to_string(),
                    has_tls13_or_higher: false,
                });
            }
        }

        let supported_protocols = self.count_supported_protocols(&protocol_tester).await?;
        tracing::debug!(
            "Server supports {} TLS/SSL protocol version(s) (excluding SSL 2 and QUIC)",
            supported_protocols.len()
        );

        self.build_scsv_result(&supported_protocols).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{COMPRESSION_NULL, CONTENT_TYPE_ALERT, VERSION_TLS_1_2};
    use crate::protocols::Protocol;

    #[test]
    fn test_fallback_scsv_result() {
        let result = FallbackScsvTestResult {
            supported: true,
            accepts_downgrade: false,
            vulnerable: false,
            inconclusive: false,
            not_applicable: false,
            details: "Test".to_string(),
            has_tls13_or_higher: false,
        };
        assert!(result.supported);
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_client_hello_with_scsv() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(0x0303, true);

        assert!(hello.len() > 50);
        let has_scsv = hello.windows(2).any(|window| window == [0x56, 0x00]);
        assert!(has_scsv);
    }

    #[test]
    fn test_client_hello_without_scsv() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(0x0303, false);

        let has_scsv = hello.windows(2).any(|window| window == [0x56, 0x00]);
        assert!(!has_scsv);
    }

    #[test]
    fn test_with_test_all_ips_sets_flag() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target).with_test_all_ips(true);
        assert!(tester.test_all_ips);
    }

    #[test]
    fn test_format_protocol_list_and_select_fallback() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let list = tester.format_protocol_list(&[Protocol::TLS12, Protocol::TLS13]);
        assert!(list.contains("TLS 1.2"));
        assert!(list.contains("TLS 1.3"));

        let fallback =
            tester.select_fallback_protocol(&[Protocol::TLS10, Protocol::TLS12], Protocol::TLS12);
        assert_eq!(fallback, Some(Protocol::TLS10));

        let none = tester.select_fallback_protocol(&[Protocol::TLS12], Protocol::TLS12);
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn test_rejects_inappropriate_fallback_early_returns() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let mut tester = FallbackScsvTester::new(&target);
        tester.max_supported_protocol = Some(Protocol::SSLv3);
        let support = tester
            .test_rejects_inappropriate_fallback(&[Protocol::SSLv3])
            .await
            .expect("test assertion should succeed");
        assert!(!support.supported);
        assert!(support.inconclusive);

        tester.max_supported_protocol = Some(Protocol::QUIC);
        let support = tester
            .test_rejects_inappropriate_fallback(&[Protocol::QUIC])
            .await
            .expect("test assertion should succeed");
        assert!(!support.supported);
        assert!(support.not_applicable);

        tester.max_supported_protocol = Some(Protocol::TLS12);
        let support = tester
            .test_rejects_inappropriate_fallback(&[Protocol::TLS12])
            .await
            .expect("test assertion should succeed");
        assert!(!support.supported);
        assert!(support.inconclusive);
    }

    #[tokio::test]
    async fn test_single_supported_protocol_result_is_inconclusive() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let mut tester = FallbackScsvTester::new(&target);
        tester.max_supported_protocol = Some(Protocol::TLS12);

        let result = tester
            .build_scsv_result(&[Protocol::TLS12])
            .await
            .expect("test assertion should succeed");

        assert!(result.inconclusive);
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_select_fallback_protocol() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = FallbackScsvTester::new(&target);
        let supported = vec![Protocol::TLS10, Protocol::TLS11, Protocol::TLS12];
        let fallback = tester.select_fallback_protocol(&supported, Protocol::TLS12);
        assert_eq!(fallback, Some(Protocol::TLS11));
    }

    #[test]
    fn test_format_protocol_list() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = FallbackScsvTester::new(&target);
        let protocols = vec![Protocol::TLS10, Protocol::TLS12];
        let formatted = tester.format_protocol_list(&protocols);
        assert!(formatted.contains("TLS 1.0"));
        assert!(formatted.contains("TLS 1.2"));
    }

    #[test]
    fn test_format_protocol_list_empty() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = FallbackScsvTester::new(&target);
        let formatted = tester.format_protocol_list(&[]);
        assert!(formatted.is_empty());
    }

    #[test]
    fn test_scsv_support_variants() {
        let supported = crate::protocols::fallback_scsv::model::ScsvSupport::supported();
        assert!(supported.supported);
        assert!(!supported.vulnerable);
        assert!(!supported.accepts_downgrade);
        assert!(!supported.inconclusive);
        assert!(!supported.not_applicable);

        let not_supported = crate::protocols::fallback_scsv::model::ScsvSupport::not_supported();
        assert!(!not_supported.supported);
        assert!(not_supported.vulnerable);
        assert!(not_supported.accepts_downgrade);
        assert!(!not_supported.inconclusive);
        assert!(!not_supported.not_applicable);

        let inconclusive = crate::protocols::fallback_scsv::model::ScsvSupport::inconclusive();
        assert!(!inconclusive.supported);
        assert!(!inconclusive.vulnerable);
        assert!(!inconclusive.accepts_downgrade);
        assert!(inconclusive.inconclusive);
        assert!(!inconclusive.not_applicable);

        let not_applicable = crate::protocols::fallback_scsv::model::ScsvSupport::not_applicable();
        assert!(!not_applicable.supported);
        assert!(!not_applicable.vulnerable);
        assert!(!not_applicable.accepts_downgrade);
        assert!(!not_applicable.inconclusive);
        assert!(not_applicable.not_applicable);
    }

    #[test]
    fn test_baseline_fallback_accepted_logic() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = FallbackScsvTester::new(&target);

        let mut buffer = [0u8; 8];
        assert!(tester.baseline_fallback_accepted(Ok(Ok(5)), &buffer));

        buffer[0] = CONTENT_TYPE_ALERT;
        assert!(!tester.baseline_fallback_accepted(Ok(Ok(7)), &buffer));

        let err = std::io::Error::other("read error");
        assert!(!tester.baseline_fallback_accepted(Ok(Err(err)), &buffer));
    }

    #[test]
    fn test_client_hello_length_fields_with_scsv() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(VERSION_TLS_1_2, true);

        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5);

        let hs_len = ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | (hello[8] as usize);
        assert_eq!(hs_len, hello.len() - 9);
    }

    #[test]
    fn test_client_hello_length_fields_without_scsv() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(VERSION_TLS_1_2, false);

        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5);

        let hs_len = ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | (hello[8] as usize);
        assert_eq!(hs_len, hello.len() - 9);
    }

    #[test]
    fn test_client_hello_includes_null_compression() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(VERSION_TLS_1_2, true);
        assert!(hello.contains(&COMPRESSION_NULL));
    }

    #[test]
    fn test_client_hello_sni_extension_encodes_hostname() {
        let hostname = "example.com";
        let target = Target::with_ips(
            hostname.to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(VERSION_TLS_1_2, true);

        let cipher_count = 3usize;
        let ext_len_pos = 5 + 1 + 3 + 2 + 32 + 1 + 2 + cipher_count * 2 + 1 + 1;

        // Bounds check before accessing hello array
        assert!(
            ext_len_pos + 9 < hello.len(),
            "ClientHello too short for SNI extraction"
        );

        let ext_len = u16::from_be_bytes([hello[ext_len_pos], hello[ext_len_pos + 1]]) as usize;
        assert_eq!(ext_len, hello.len() - ext_len_pos - 2);

        let sni_type_pos = ext_len_pos + 2;
        assert_eq!(hello[sni_type_pos], 0x00);
        assert_eq!(hello[sni_type_pos + 1], 0x00);

        let sni_len =
            u16::from_be_bytes([hello[sni_type_pos + 2], hello[sni_type_pos + 3]]) as usize;
        let list_len =
            u16::from_be_bytes([hello[sni_type_pos + 4], hello[sni_type_pos + 5]]) as usize;
        let name_len =
            u16::from_be_bytes([hello[sni_type_pos + 7], hello[sni_type_pos + 8]]) as usize;
        let name_start = sni_type_pos + 9;
        let name_end = name_start + name_len;

        assert_eq!(sni_len, hostname.len() + 5);
        assert_eq!(list_len, hostname.len() + 3);
        assert_eq!(&hello[name_start..name_end], hostname.as_bytes());
    }
}
