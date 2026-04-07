use super::analysis::analyze_cipher_details;
use super::{
    CipherDetails, CipherPerProtocolAnalysis, ProtocolAdvancedTester, ProtocolCipherSupport,
    TlsTruncationAnalysis,
};
use crate::Result;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use tokio::time::Duration;

const TEST_CIPHERS: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
    "RC4-MD5",
];

impl ProtocolAdvancedTester {
    pub async fn test_tls_truncation(&self) -> Result<TlsTruncationAnalysis> {
        let accepts_truncated_hmac = false;
        let accepts_no_close_notify = false;
        let vulnerable = false;
        let tested = false;

        let details =
            "TLS truncation test inconclusive - active truncated-HMAC and close_notify probes are not implemented"
                .to_string();

        Ok(TlsTruncationAnalysis {
            vulnerable,
            accepts_truncated_hmac,
            accepts_no_close_notify,
            tested,
            details,
        })
    }

    pub async fn test_ciphers_per_protocol(&self) -> Result<CipherPerProtocolAnalysis> {
        let protocols = vec![
            ("SSLv3", SslVersion::SSL3),
            ("TLS 1.0", SslVersion::TLS1),
            ("TLS 1.1", SslVersion::TLS1_1),
            ("TLS 1.2", SslVersion::TLS1_2),
            ("TLS 1.3", SslVersion::TLS1_3),
        ];

        let mut protocol_results = Vec::new();
        let mut total_ciphers = 0;

        for (protocol_name, ssl_version) in protocols {
            if let Ok(ciphers) = self.enumerate_protocol_ciphers(ssl_version).await {
                let cipher_count = ciphers.len();
                total_ciphers += cipher_count;
                protocol_results.push(ProtocolCipherSupport {
                    protocol: protocol_name.to_string(),
                    supported_ciphers: ciphers,
                    cipher_count,
                });
            }
        }

        let total_protocols = protocol_results.len();
        let details = format!(
            "Found {} cipher suites across {} protocols",
            total_ciphers, total_protocols
        );

        Ok(CipherPerProtocolAnalysis {
            protocols: protocol_results,
            total_ciphers,
            total_protocols,
            details,
        })
    }

    pub(super) async fn test_cipher_support(&self, cipher: &str) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list(cipher)?;
        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn enumerate_protocol_ciphers(&self, protocol: SslVersion) -> Result<Vec<CipherDetails>> {
        let mut supported_ciphers = Vec::new();

        for cipher in TEST_CIPHERS {
            if let Ok(true) = self.test_cipher_with_protocol(cipher, protocol).await {
                supported_ciphers.push(analyze_cipher_details(cipher));
            }
        }

        Ok(supported_ciphers)
    }

    async fn test_cipher_with_protocol(&self, cipher: &str, protocol: SslVersion) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(protocol))?;
        builder.set_max_proto_version(Some(protocol))?;
        builder.set_cipher_list(cipher)?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
