// TLS intolerance façade.

#[path = "intolerance/client_hello.rs"]
mod client_hello;
#[path = "intolerance/network.rs"]
mod network;
#[path = "intolerance/orchestration.rs"]
mod orchestration;

use crate::utils::network::Target;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Result of intolerance testing
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntoleranceTestResult {
    pub extension_intolerance: bool,
    pub version_intolerance: bool,
    pub long_handshake_intolerance: bool,
    pub incorrect_sni_alerts: bool,
    pub uses_common_dh_primes: bool,
    pub details: HashMap<String, String>,
}

/// TLS Intolerance Tester
pub struct IntoleranceTester {
    pub(super) target: Target,
    pub(super) sni_hostname: Option<String>,
    pub(super) connect_timeout: Duration,
    pub(super) read_timeout: Duration,
}

impl IntoleranceTester {
    /// Create new intolerance tester
    pub fn new(target: Target) -> Self {
        Self {
            target,
            sni_hostname: None,
            connect_timeout: crate::constants::DEFAULT_CONNECT_TIMEOUT,
            read_timeout: crate::constants::DEFAULT_READ_TIMEOUT,
        }
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        CONTENT_TYPE_HANDSHAKE, EXTENSION_EC_POINT_FORMATS, EXTENSION_SERVER_NAME,
        EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_SUPPORTED_GROUPS, HANDSHAKE_TYPE_CLIENT_HELLO,
        VERSION_TLS_1_0,
    };

    fn parse_client_hello_extensions(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
        assert!(hello.len() >= 5);
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        let record_end = 5 + record_len;
        assert!(record_end <= hello.len());

        let mut offset = 5;
        assert_eq!(hello[offset], HANDSHAKE_TYPE_CLIENT_HELLO);
        offset += 1;
        let hs_len = ((hello[offset] as usize) << 16)
            | ((hello[offset + 1] as usize) << 8)
            | hello[offset + 2] as usize;
        offset += 3;
        assert!(offset + hs_len <= hello.len());

        offset += 2 + 32;
        let session_len = hello[offset] as usize;
        offset += 1 + session_len;

        let cipher_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2 + cipher_len;

        let comp_len = hello[offset] as usize;
        offset += 1 + comp_len;

        if offset >= record_end {
            return Vec::new();
        }

        let extensions_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        let end = offset + extensions_len;
        assert!(end <= record_end);

        let mut extensions = Vec::new();
        while offset + 4 <= end {
            let ext_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
            let ext_len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
            offset += 4;

            // Bounds check before slicing
            if offset + ext_len > hello.len() {
                break;
            }

            let data = hello[offset..offset + ext_len].to_vec();
            offset += ext_len;
            extensions.push((ext_type, data));
        }

        extensions
    }

    #[test]
    fn test_minimal_client_hello_has_no_extensions_additional() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_minimal_client_hello()
            .expect("test assertion should succeed");
        let extensions = parse_client_hello_extensions(&hello);
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_load_common_primes() {
        let primes =
            IntoleranceTester::load_common_primes().expect("test assertion should succeed");
        assert!(!primes.is_empty());
        assert!(primes.len() > 10);
    }

    #[test]
    fn test_intolerance_result_default() {
        let result = IntoleranceTestResult::default();
        assert!(!result.extension_intolerance);
        assert!(!result.version_intolerance);
        assert!(!result.long_handshake_intolerance);
        assert!(!result.incorrect_sni_alerts);
        assert!(!result.uses_common_dh_primes);
        assert!(result.details.is_empty());
    }

    #[tokio::test]
    async fn test_build_minimal_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_minimal_client_hello()
            .expect("test assertion should succeed");

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[5], 0x01);
    }

    #[tokio::test]
    async fn test_build_extended_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_extended_client_hello()
            .expect("test assertion should succeed");

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[5], 0x01);

        let minimal = tester
            .build_minimal_client_hello()
            .expect("test assertion should succeed");
        assert!(hello.len() > minimal.len());
    }

    #[tokio::test]
    async fn test_build_long_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_long_client_hello()
            .expect("test assertion should succeed");

        assert!(hello.len() > 256);
    }

    #[tokio::test]
    async fn test_build_versioned_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_versioned_client_hello(VERSION_TLS_1_0)
            .expect("test assertion should succeed");

        assert_eq!(hello[1], (VERSION_TLS_1_0 >> 8) as u8);
        assert_eq!(hello[2], (VERSION_TLS_1_0 & 0xff) as u8);
        assert_eq!(hello[0], CONTENT_TYPE_HANDSHAKE);
    }

    #[tokio::test]
    async fn test_build_invalid_sni_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_invalid_sni_client_hello()
            .expect("test assertion should succeed");

        assert_eq!(hello[0], CONTENT_TYPE_HANDSHAKE);
        assert_eq!(hello[5], HANDSHAKE_TYPE_CLIENT_HELLO);
        assert!(hello.len() > 50);
    }

    #[test]
    fn test_minimal_client_hello_has_no_extensions() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_minimal_client_hello()
            .expect("test assertion should succeed");
        let extensions = parse_client_hello_extensions(&hello);
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_extended_client_hello_includes_expected_extensions() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_extended_client_hello()
            .expect("test assertion should succeed");
        let types: Vec<u16> = parse_client_hello_extensions(&hello)
            .into_iter()
            .map(|(t, _)| t)
            .collect();

        assert!(types.contains(&EXTENSION_SERVER_NAME));
        assert!(types.contains(&EXTENSION_SUPPORTED_GROUPS));
        assert!(types.contains(&EXTENSION_EC_POINT_FORMATS));
        assert!(types.contains(&EXTENSION_SIGNATURE_ALGORITHMS));
    }

    #[test]
    fn test_long_client_hello_includes_padding_extension() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_long_client_hello()
            .expect("test assertion should succeed");
        let types: Vec<u16> = parse_client_hello_extensions(&hello)
            .into_iter()
            .map(|(t, _)| t)
            .collect();

        assert!(types.contains(&0x0015));
    }

    #[test]
    fn test_invalid_sni_client_hello_contains_invalid_hostname() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = IntoleranceTester::new(target);
        let hello = tester
            .build_invalid_sni_client_hello()
            .expect("test assertion should succeed");
        let extensions = parse_client_hello_extensions(&hello);
        let sni = extensions
            .into_iter()
            .find(|(t, _)| *t == EXTENSION_SERVER_NAME)
            .expect("SNI extension should exist");
        let data = sni.1;
        assert!(data.len() >= 5);
        let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let hostname =
            std::str::from_utf8(&data[5..5 + name_len]).expect("hostname should be utf8");
        assert_eq!(hostname, "invalid.nonexistent.example.com");
    }
}
