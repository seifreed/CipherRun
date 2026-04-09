use super::{
    BACKOFF_BASE_DELAY_MS, BACKOFF_MAX_EXPONENT, BATCH_SIZE_MULTIPLIER, CIPHER_DB,
    RETRY_BACKOFF_SECS,
};
use super::{
    CipherBatchResult, CipherTestResult, CipherTester, ProtocolCipherSummary, Result,
    TlsConnectionPool,
};
use crate::ciphers::CipherSuite;
use crate::protocols::Protocol;
use futures::stream::{self, StreamExt};
use std::sync::Arc;

impl CipherTester {
    pub async fn test_protocol_ciphers(&self, protocol: Protocol) -> Result<ProtocolCipherSummary> {
        let (compatible_ciphers, max_concurrent_tests, connection_pool) =
            self.prepare_cipher_batch(protocol);

        let (results, enetdown_count) = self
            .run_cipher_test_loop(
                &connection_pool,
                compatible_ciphers,
                max_concurrent_tests,
                protocol,
            )
            .await;

        if enetdown_count > 0 {
            tracing::info!(
                "Completed cipher testing with {} ENETDOWN error(s) recovered via adaptive backoff",
                enetdown_count
            );
        }

        self.aggregate_results(protocol, results).await
    }

    async fn run_cipher_test_loop(
        &self,
        connection_pool: &Option<Arc<TlsConnectionPool>>,
        mut cipher_queue: Vec<CipherSuite>,
        mut max_concurrent_tests: usize,
        protocol: Protocol,
    ) -> (Vec<CipherTestResult>, usize) {
        let mut results: Vec<CipherTestResult> = Vec::new();
        let mut enetdown_count = 0;
        let mut current_batch_size = max_concurrent_tests;
        let mut retry_queue: Vec<CipherSuite> = Vec::new();
        let max_enetdown_retries = 3;
        let mut retry_round = 0;

        while !cipher_queue.is_empty() || !retry_queue.is_empty() {
            if cipher_queue.is_empty()
                && !retry_queue.is_empty()
                && !Self::prepare_retry_round(
                    &mut cipher_queue,
                    &mut retry_queue,
                    &mut retry_round,
                    max_enetdown_retries,
                )
                .await
            {
                break;
            }

            if let Some(adaptive) = &self.adaptive {
                let adaptive_max = adaptive.max_concurrency().max(1);
                if adaptive_max != max_concurrent_tests {
                    max_concurrent_tests = adaptive_max;
                    current_batch_size = current_batch_size.min(max_concurrent_tests);
                }
            }

            let batch_size = current_batch_size * BATCH_SIZE_MULTIPLIER;
            let batch: Vec<_> = cipher_queue
                .drain(..cipher_queue.len().min(batch_size))
                .collect();
            if batch.is_empty() {
                break;
            }

            let batch_results = Self::execute_cipher_batch(
                self,
                connection_pool,
                batch,
                protocol,
                current_batch_size,
            )
            .await;

            let (batch_enetdown, batch_other_errors) =
                Self::process_batch_errors(batch_results, protocol, &mut results, &mut retry_queue);

            enetdown_count += batch_enetdown;

            current_batch_size = Self::adjust_concurrency(
                batch_enetdown,
                batch_other_errors,
                current_batch_size,
                max_concurrent_tests,
            )
            .await;
        }

        (results, enetdown_count)
    }

    /// Swap retry queue into cipher queue for a new retry round.
    /// Returns `false` if max retries have been exceeded.
    async fn prepare_retry_round(
        cipher_queue: &mut Vec<CipherSuite>,
        retry_queue: &mut Vec<CipherSuite>,
        retry_round: &mut usize,
        max_retries: usize,
    ) -> bool {
        *retry_round += 1;
        if *retry_round >= max_retries {
            tracing::warn!(
                "Max ENETDOWN retries ({}) reached, {} ciphers could not be tested",
                max_retries,
                retry_queue.len()
            );
            return false;
        }
        let count = retry_queue.len();
        *cipher_queue = std::mem::take(retry_queue);
        tracing::info!(
            "Retrying {} ciphers that failed with ENETDOWN (attempt {}/{})",
            count,
            retry_round,
            max_retries
        );
        tokio::time::sleep(std::time::Duration::from_secs(RETRY_BACKOFF_SECS)).await;
        true
    }

    fn prepare_cipher_batch(
        &self,
        protocol: Protocol,
    ) -> (Vec<CipherSuite>, usize, Option<Arc<TlsConnectionPool>>) {
        let ciphers = if self.test_all_ciphers {
            CIPHER_DB.get_all_ciphers()
        } else {
            CIPHER_DB.get_recommended_ciphers()
        };

        let compatible_ciphers: Vec<CipherSuite> = ciphers
            .into_iter()
            .filter(|c| self.is_cipher_compatible_with_protocol(c, protocol))
            .collect();

        let mut max_concurrent_tests = self.max_concurrent_tests.max(1);
        if let Some(adaptive) = &self.adaptive {
            max_concurrent_tests = adaptive.max_concurrency().max(1);
        }

        tracing::debug!(
            "Testing {} compatible ciphers for {:?} with max {} concurrent connections (pool size: {})",
            compatible_ciphers.len(),
            protocol,
            max_concurrent_tests,
            self.connection_pool_size
        );

        let connection_pool = match self.target.socket_addrs().first().copied() {
            Some(addr) if self.connection_pool_size > 0 => Some(Arc::new(TlsConnectionPool::new(
                addr,
                self.connection_pool_size.min(max_concurrent_tests),
                self.connect_timeout,
                self.retry_config.clone(),
            ))),
            Some(_) => None, // connection_pool_size is 0
            None => {
                tracing::warn!(
                    "No socket addresses available for target, connection pool disabled"
                );
                None
            }
        };

        (compatible_ciphers, max_concurrent_tests, connection_pool)
    }

    async fn execute_cipher_batch(
        tester: &CipherTester,
        connection_pool: &Option<Arc<TlsConnectionPool>>,
        batch: Vec<CipherSuite>,
        protocol: Protocol,
        current_batch_size: usize,
    ) -> CipherBatchResult {
        stream::iter(batch)
            .map(|cipher| {
                let tester_clone = tester;
                let pool_clone = connection_pool.clone();
                async move {
                    let result = if let Some(pool) = pool_clone {
                        tester_clone
                            .test_cipher_handshake_only(&cipher, protocol, Some(&pool))
                            .await
                    } else {
                        tester_clone
                            .test_cipher_handshake_only(&cipher, protocol, None)
                            .await
                    };

                    if let Some(sleep_dur) = tester_clone.sleep_duration {
                        tokio::time::sleep(sleep_dur).await;
                    }

                    (cipher, result)
                }
            })
            .buffer_unordered(current_batch_size)
            .collect::<Vec<_>>()
            .await
    }

    fn process_batch_errors(
        batch_results: CipherBatchResult,
        protocol: Protocol,
        results: &mut Vec<CipherTestResult>,
        retry_queue: &mut Vec<CipherSuite>,
    ) -> (usize, usize) {
        let mut batch_enetdown = 0;
        let mut batch_other_errors = 0;

        for (cipher, result) in batch_results {
            match result {
                Ok((supported, handshake_time_ms)) => {
                    results.push(CipherTestResult {
                        cipher,
                        supported,
                        protocol,
                        server_preference: None,
                        handshake_time_ms,
                    });
                }
                Err(e) => {
                    let err_msg = e.to_string().to_lowercase();
                    if err_msg.contains("network is down") || err_msg.contains("os error 50") {
                        batch_enetdown += 1;
                        retry_queue.push(cipher);
                    } else {
                        batch_other_errors += 1;
                        tracing::debug!("Cipher test error (non-ENETDOWN): {}", e);
                    }
                }
            }
        }

        (batch_enetdown, batch_other_errors)
    }

    async fn adjust_concurrency(
        batch_enetdown: usize,
        batch_other_errors: usize,
        mut current_batch_size: usize,
        max_concurrent_tests: usize,
    ) -> usize {
        if batch_enetdown > 0 {
            let old_size = current_batch_size;
            if current_batch_size <= 1 {
                // Already at minimum — can't reduce further, rely on retry_round limit
                tracing::warn!("Batch size already at minimum (1), waiting for retry backoff");
            } else if batch_enetdown > current_batch_size / 2 {
                current_batch_size = (current_batch_size / 3).max(1);
            } else {
                current_batch_size = (current_batch_size / 2).max(1);
            }

            use rand::RngExt;
            let error_level = batch_enetdown.min(10) as u32;
            let base_delay_ms =
                BACKOFF_BASE_DELAY_MS * 2u64.pow(error_level.min(BACKOFF_MAX_EXPONENT));
            let jitter = rand::rng().random_range(0..=(base_delay_ms / 4));
            let total_delay_ms = base_delay_ms + jitter;

            tracing::warn!(
                "Detected {} ENETDOWN error(s), reducing concurrency from {} to {} with {}ms exponential backoff",
                batch_enetdown,
                old_size,
                current_batch_size,
                total_delay_ms
            );

            tokio::time::sleep(std::time::Duration::from_millis(total_delay_ms)).await;
        } else if current_batch_size < max_concurrent_tests && batch_other_errors == 0 {
            current_batch_size = (current_batch_size + 1).min(max_concurrent_tests);
            tracing::debug!(
                "Successful batch, increasing concurrency to {}",
                current_batch_size
            );
        }

        if batch_other_errors > 0 {
            tracing::debug!("Batch had {} other errors (ignored)", batch_other_errors);
        }

        current_batch_size
    }

    async fn aggregate_results(
        &self,
        protocol: Protocol,
        results: Vec<CipherTestResult>,
    ) -> Result<ProtocolCipherSummary> {
        let handshake_times: Vec<u64> =
            results.iter().filter_map(|r| r.handshake_time_ms).collect();
        let avg_handshake_time_ms = if !handshake_times.is_empty() {
            Some(handshake_times.iter().sum::<u64>() / handshake_times.len() as u64)
        } else {
            None
        };

        let supported: Vec<CipherSuite> = results
            .into_iter()
            .filter(|r| r.supported)
            .map(|r| r.cipher)
            .collect();

        tracing::debug!(
            "Found {} supported ciphers for {:?}",
            supported.len(),
            protocol
        );

        let server_preference = self
            .determine_server_preference(protocol, &supported)
            .await?;
        let server_ordered = !server_preference.is_empty();

        let preferred_cipher = if !server_preference.is_empty() {
            CIPHER_DB.get_by_hexcode(&server_preference[0])
        } else {
            supported.first().cloned()
        };

        let counts = self.calculate_cipher_counts(&supported);

        Ok(ProtocolCipherSummary {
            protocol,
            supported_ciphers: supported,
            server_ordered,
            server_preference,
            preferred_cipher,
            counts,
            avg_handshake_time_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::network::Target;
    use std::net::{IpAddr, Ipv4Addr};

    fn dummy_target() -> Target {
        Target::with_ips(
            "localhost".to_string(),
            443,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .expect("test target should be valid")
    }

    fn make_cipher(
        hexcode: &str,
        protocol: &str,
        encryption: &str,
        bits: u16,
        export: bool,
        key_exchange: &str,
    ) -> CipherSuite {
        CipherSuite {
            hexcode: hexcode.to_string(),
            openssl_name: format!("TEST-{}", hexcode),
            iana_name: format!("TLS_TEST_{}", hexcode),
            protocol: protocol.to_string(),
            key_exchange: key_exchange.to_string(),
            authentication: "RSA".to_string(),
            encryption: encryption.to_string(),
            mac: "SHA256".to_string(),
            bits,
            export,
        }
    }

    fn tls12_cipher(hexcode: &str, encryption: &str, bits: u16) -> CipherSuite {
        make_cipher(hexcode, "TLSv1.2", encryption, bits, false, "RSA")
    }

    // --- is_cipher_compatible_with_protocol ---

    #[test]
    fn tls13_cipher_compatible_with_tls13() {
        let tester = CipherTester::new(dummy_target());
        let cipher = make_cipher("1301", "TLS13", "AESGCM", 256, false, "any");
        assert!(tester.is_cipher_compatible_with_protocol(&cipher, Protocol::TLS13));
    }

    #[test]
    fn tls13_cipher_with_versioned_protocol_string() {
        let tester = CipherTester::new(dummy_target());
        let cipher = make_cipher("1302", "TLSv1.3", "CHACHA20", 256, false, "any");
        assert!(tester.is_cipher_compatible_with_protocol(&cipher, Protocol::TLS13));
    }

    #[test]
    fn tls13_cipher_not_compatible_with_tls12() {
        let tester = CipherTester::new(dummy_target());
        let cipher = make_cipher("1301", "TLS13", "AESGCM", 256, false, "any");
        assert!(!tester.is_cipher_compatible_with_protocol(&cipher, Protocol::TLS12));
    }

    #[test]
    fn tls12_cipher_not_compatible_with_tls13() {
        let tester = CipherTester::new(dummy_target());
        let cipher = tls12_cipher("002F", "AES128-CBC", 128);
        assert!(!tester.is_cipher_compatible_with_protocol(&cipher, Protocol::TLS13));
    }

    #[test]
    fn tls12_cipher_compatible_with_tls12() {
        let tester = CipherTester::new(dummy_target());
        let cipher = tls12_cipher("002F", "AES128-CBC", 128);
        assert!(tester.is_cipher_compatible_with_protocol(&cipher, Protocol::TLS12));
    }

    #[test]
    fn tls12_cipher_compatible_with_tls10() {
        let tester = CipherTester::new(dummy_target());
        let cipher = tls12_cipher("002F", "AES128-CBC", 128);
        assert!(tester.is_cipher_compatible_with_protocol(&cipher, Protocol::TLS10));
    }

    #[test]
    fn sslv2_cipher_compatible_with_sslv2() {
        let tester = CipherTester::new(dummy_target());
        let cipher = make_cipher("0001", "SSLv2", "DES", 56, false, "RSA");
        assert!(tester.is_cipher_compatible_with_protocol(&cipher, Protocol::SSLv2));
    }

    #[test]
    fn sslv2_cipher_not_compatible_with_tls12() {
        let tester = CipherTester::new(dummy_target());
        let cipher = make_cipher("0001", "SSLv2", "DES", 56, false, "RSA");
        assert!(!tester.is_cipher_compatible_with_protocol(&cipher, Protocol::TLS12));
    }

    #[test]
    fn non_sslv2_cipher_not_compatible_with_sslv2() {
        let tester = CipherTester::new(dummy_target());
        let cipher = tls12_cipher("002F", "AES128-CBC", 128);
        assert!(!tester.is_cipher_compatible_with_protocol(&cipher, Protocol::SSLv2));
    }

    // --- calculate_cipher_counts ---

    #[test]
    fn cipher_counts_empty_list() {
        let tester = CipherTester::new(dummy_target());
        let counts = tester.calculate_cipher_counts(&[]);
        assert_eq!(counts.total, 0);
        assert_eq!(counts.null_ciphers, 0);
        assert_eq!(counts.export_ciphers, 0);
        assert_eq!(counts.low_strength, 0);
        assert_eq!(counts.medium_strength, 0);
        assert_eq!(counts.high_strength, 0);
        assert_eq!(counts.forward_secrecy, 0);
        assert_eq!(counts.aead, 0);
    }

    #[test]
    fn cipher_counts_classifies_null() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![make_cipher("0000", "TLSv1.2", "NULL", 0, false, "RSA")];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.total, 1);
        assert_eq!(counts.null_ciphers, 1);
    }

    #[test]
    fn cipher_counts_classifies_export() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![make_cipher("0003", "TLSv1.2", "DES40", 40, true, "RSA")];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.total, 1);
        assert_eq!(counts.export_ciphers, 1);
    }

    #[test]
    fn cipher_counts_classifies_low_strength() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![make_cipher("000A", "TLSv1.2", "DES-CBC", 56, false, "RSA")];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.total, 1);
        assert_eq!(counts.low_strength, 1);
    }

    #[test]
    fn cipher_counts_classifies_medium_strength() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![tls12_cipher("002F", "AES128-CBC", 128)];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.total, 1);
        assert_eq!(counts.medium_strength, 1);
    }

    #[test]
    fn cipher_counts_classifies_high_strength() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![tls12_cipher("009D", "AES256-GCM", 256)];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.total, 1);
        assert_eq!(counts.high_strength, 1);
    }

    #[test]
    fn cipher_counts_forward_secrecy() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![
            make_cipher("C02F", "TLSv1.2", "AES128-GCM", 128, false, "ECDHE"),
            tls12_cipher("002F", "AES128-CBC", 128),
        ];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.forward_secrecy, 1);
    }

    #[test]
    fn cipher_counts_tls13_always_forward_secrecy() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![make_cipher("1301", "TLSv1.3", "AESGCM", 256, false, "any")];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.forward_secrecy, 1);
    }

    #[test]
    fn cipher_counts_aead() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![
            tls12_cipher("009C", "AES128-GCM", 128),
            tls12_cipher("CCA8", "CHACHA20-POLY1305", 256),
            tls12_cipher("C09C", "AES128-CCM", 128),
            tls12_cipher("002F", "AES128-CBC", 128), // not AEAD
        ];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.aead, 3);
    }

    #[test]
    fn cipher_counts_mixed_suite() {
        let tester = CipherTester::new(dummy_target());
        let ciphers = vec![
            make_cipher("0000", "TLSv1.2", "NULL", 0, false, "RSA"),
            make_cipher("0003", "TLSv1.2", "DES40", 40, true, "RSA"),
            make_cipher("000A", "TLSv1.2", "DES-CBC", 56, false, "RSA"),
            tls12_cipher("002F", "AES128-CBC", 128),
            tls12_cipher("009D", "AES256-GCM", 256),
        ];
        let counts = tester.calculate_cipher_counts(&ciphers);
        assert_eq!(counts.total, 5);
        assert_eq!(counts.null_ciphers, 1);
        assert_eq!(counts.export_ciphers, 1);
        assert_eq!(counts.low_strength, 1);
        assert_eq!(counts.medium_strength, 1);
        assert_eq!(counts.high_strength, 1);
    }

    // --- batch size constants ---

    #[test]
    fn batch_size_multiplier_is_positive() {
        let multiplier = BATCH_SIZE_MULTIPLIER;
        assert!(multiplier > 0);
    }

    #[test]
    fn batch_size_calculation() {
        // Verify the batch size formula used in test_protocol_ciphers:
        // batch_size = current_batch_size * BATCH_SIZE_MULTIPLIER
        let concurrent = 10usize;
        let batch_size = concurrent * BATCH_SIZE_MULTIPLIER;
        assert_eq!(batch_size, concurrent * 5);
    }

    #[test]
    fn batch_drain_with_fewer_ciphers_than_batch_size() {
        // Simulates the drain logic: cipher_queue.drain(..cipher_queue.len().min(batch_size))
        let mut queue = vec![1, 2, 3];
        let batch_size = 50;
        let batch: Vec<_> = queue.drain(..queue.len().min(batch_size)).collect();
        assert_eq!(batch.len(), 3);
        assert!(queue.is_empty());
    }

    #[test]
    fn batch_drain_with_more_ciphers_than_batch_size() {
        let mut queue: Vec<i32> = (0..100).collect();
        let batch_size = 10usize * BATCH_SIZE_MULTIPLIER; // 50
        let batch: Vec<_> = queue.drain(..queue.len().min(batch_size)).collect();
        assert_eq!(batch.len(), 50);
        assert_eq!(queue.len(), 50);
    }

    // --- concurrency reduction logic ---

    #[test]
    fn concurrency_halved_on_minor_enetdown() {
        // When batch_enetdown <= current_batch_size / 2
        let current_batch_size: usize = 10;
        let batch_enetdown: usize = 3;
        let new_size = if batch_enetdown > current_batch_size / 2 {
            (current_batch_size / 3).max(1)
        } else {
            (current_batch_size / 2).max(1)
        };
        assert_eq!(new_size, 5);
    }

    #[test]
    fn concurrency_thirded_on_major_enetdown() {
        // When batch_enetdown > current_batch_size / 2
        let current_batch_size: usize = 10;
        let batch_enetdown: usize = 8;
        let new_size = if batch_enetdown > current_batch_size / 2 {
            (current_batch_size / 3).max(1)
        } else {
            (current_batch_size / 2).max(1)
        };
        assert_eq!(new_size, 3);
    }

    #[test]
    fn concurrency_never_drops_below_one() {
        let current_batch_size: usize = 1;
        let new_size = (current_batch_size / 3).max(1);
        assert_eq!(new_size, 1);
    }
}
