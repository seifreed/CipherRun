use super::{
    BACKOFF_BASE_DELAY_MS, BACKOFF_MAX_EXPONENT, BATCH_SIZE_MULTIPLIER, CIPHER_DB,
    RETRY_BACKOFF_SECS, SERVER_HELLO_MIN_SIZE, SESSION_ID_LENGTH_OFFSET, CIPHER_SUITE_BASE_OFFSET,
};
use super::{
    BUFFER_SIZE_DEFAULT, CONTENT_TYPE_HANDSHAKE, CipherBatchResult, CipherCounts, CipherStrength,
    CipherTestResult, CipherTester, HANDSHAKE_TYPE_SERVER_HELLO, ProtocolCipherSummary, Result,
    TlsConnectionPool, timeout,
};
use crate::ciphers::CipherSuite;
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

impl CipherTester {
    pub async fn test_protocol_ciphers(&self, protocol: Protocol) -> Result<ProtocolCipherSummary> {
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

        let connection_pool = if self.connection_pool_size > 0 {
            let addr = self.target.socket_addrs()[0];
            Some(Arc::new(TlsConnectionPool::new(
                addr,
                self.connection_pool_size.min(max_concurrent_tests),
                self.connect_timeout,
                self.retry_config.clone(),
            )))
        } else {
            None
        };

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_tests));
        let tester = Arc::new(self);

        let mut results: Vec<CipherTestResult> = Vec::new();
        let mut enetdown_count = 0;
        let mut current_batch_size = max_concurrent_tests;
        let mut cipher_queue: Vec<CipherSuite> = compatible_ciphers;
        let mut retry_queue: Vec<CipherSuite> = Vec::new();
        let max_enetdown_retries = 3;
        let mut retry_round = 0;

        while !cipher_queue.is_empty() || !retry_queue.is_empty() {
            if cipher_queue.is_empty() && !retry_queue.is_empty() {
                retry_round += 1;
                if retry_round > max_enetdown_retries {
                    tracing::warn!(
                        "Max ENETDOWN retries ({}) reached, {} ciphers could not be tested",
                        max_enetdown_retries,
                        retry_queue.len()
                    );
                    break;
                }
                cipher_queue = retry_queue;
                retry_queue = Vec::new();
                tracing::info!(
                    "Retrying {} ciphers that failed with ENETDOWN (attempt {}/{})",
                    cipher_queue.len(),
                    retry_round,
                    max_enetdown_retries
                );
                tokio::time::sleep(std::time::Duration::from_secs(RETRY_BACKOFF_SECS)).await;
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

            let batch_results: CipherBatchResult = stream::iter(batch)
                .map(|cipher| {
                    let sem = semaphore.clone();
                    let tester_clone = tester.clone();
                    let pool_clone = connection_pool.clone();
                    async move {
                        let _permit = sem.acquire().await.expect("semaphore closed");
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
                .await;

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

            enetdown_count += batch_enetdown;

            if batch_enetdown > 0 {
                let old_size = current_batch_size;
                if batch_enetdown > current_batch_size / 2 {
                    current_batch_size = (current_batch_size / 3).max(1);
                } else {
                    current_batch_size = (current_batch_size / 2).max(1);
                }

                use rand::Rng;
                let error_level = batch_enetdown.min(10) as u32;
                let base_delay_ms =
                    BACKOFF_BASE_DELAY_MS * 2u64.pow(error_level.min(BACKOFF_MAX_EXPONENT));
                let jitter = rand::thread_rng().gen_range(0..=(base_delay_ms / 4));
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
        }

        if enetdown_count > 0 {
            tracing::info!(
                "Completed cipher testing with {} ENETDOWN error(s) recovered via adaptive backoff",
                enetdown_count
            );
        }

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

    pub(super) async fn test_cipher_handshake_only(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
        pool: Option<&Arc<TlsConnectionPool>>,
    ) -> Result<(bool, Option<u64>)> {
        let hexcode = match u16::from_str_radix(&cipher.hexcode, 16) {
            Ok(h) => h,
            Err(_) => return Ok((false, None)),
        };

        let start = std::time::Instant::now();
        let supported = if let Some(pool) = pool {
            self.try_cipher_handshake_with_pool(protocol, hexcode, pool)
                .await?
        } else {
            self.try_cipher_handshake(protocol, hexcode).await?
        };

        let handshake_time_ms = if supported {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        Ok((supported, handshake_time_ms))
    }

    pub(super) async fn determine_server_preference(
        &self,
        protocol: Protocol,
        supported_ciphers: &[CipherSuite],
    ) -> Result<Vec<String>> {
        if supported_ciphers.is_empty() {
            return Ok(Vec::new());
        }

        let cipher_hexcodes: Vec<u16> = supported_ciphers
            .iter()
            .filter_map(|c| u16::from_str_radix(&c.hexcode, 16).ok())
            .collect();

        if cipher_hexcodes.len() < 2 {
            return Ok(supported_ciphers
                .iter()
                .map(|c| c.hexcode.to_string())
                .collect());
        }

        let first_choice = self
            .get_server_chosen_cipher(protocol, &cipher_hexcodes)
            .await?;
        tracing::debug!(
            "Cipher preference test 1 (original order): client offered {:04x?}, server chose {:04x?}",
            cipher_hexcodes,
            first_choice
        );

        let mut reversed = cipher_hexcodes.clone();
        reversed.reverse();
        let second_choice = self.get_server_chosen_cipher(protocol, &reversed).await?;
        tracing::debug!(
            "Cipher preference test 2 (reversed order): client offered {:04x?}, server chose {:04x?}",
            reversed,
            second_choice
        );

        let (third_choice, rotated) = if cipher_hexcodes.len() >= 3 {
            let mut rotated = cipher_hexcodes.clone();
            if let Some(last) = rotated.pop() {
                rotated.insert(0, last);
            }
            let choice = self.get_server_chosen_cipher(protocol, &rotated).await?;
            tracing::debug!(
                "Cipher preference test 3 (rotated order): client offered {:04x?}, server chose {:04x?}",
                rotated,
                choice
            );
            (choice, Some(rotated))
        } else {
            (None, None)
        };

        let analyzer = super::CipherPreferenceAnalyzer::new(
            first_choice,
            second_choice,
            third_choice,
            cipher_hexcodes,
            reversed,
            rotated,
        );

        if analyzer.is_server_preference() {
            Ok(analyzer.build_preference_order(supported_ciphers))
        } else {
            Ok(Vec::new())
        }
    }

    pub(super) async fn get_server_chosen_cipher(
        &self,
        protocol: Protocol,
        cipher_hexcodes: &[u16],
    ) -> Result<Option<u16>> {
        let addr = self.target.socket_addrs()[0];

        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(None);
            }
        }

        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(cipher_hexcodes);
        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            let mut response = vec![0u8; BUFFER_SIZE_DEFAULT];
            let bytes_read = stream.read(&mut response).await?;

            if bytes_read >= SERVER_HELLO_MIN_SIZE
                && response[0] == CONTENT_TYPE_HANDSHAKE
                && response[5] == HANDSHAKE_TYPE_SERVER_HELLO
            {
                let session_id_len = response[SESSION_ID_LENGTH_OFFSET] as usize;
                let cipher_offset = CIPHER_SUITE_BASE_OFFSET + session_id_len;

                tracing::debug!(
                    "ServerHello: session_id_len={}, cipher_offset={}, response_len={}",
                    session_id_len,
                    cipher_offset,
                    bytes_read
                );

                if bytes_read >= cipher_offset + 2 {
                    let cipher =
                        u16::from_be_bytes([response[cipher_offset], response[cipher_offset + 1]]);
                    tracing::debug!("Server chose cipher: 0x{:04x}", cipher);
                    return Ok(Some(cipher));
                }
            }

            Ok(None)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(None),
        }
    }

    pub(super) fn is_cipher_compatible_with_protocol(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
    ) -> bool {
        if matches!(protocol, Protocol::TLS13) {
            return cipher.protocol.contains("TLS13") || cipher.protocol.contains("TLSv1.3");
        }

        if matches!(protocol, Protocol::SSLv2) {
            return cipher.protocol.contains("SSLv2");
        }

        !cipher.protocol.contains("TLS13")
            && !cipher.protocol.contains("TLSv1.3")
            && !cipher.protocol.contains("SSLv2")
    }

    pub(super) fn calculate_cipher_counts(&self, ciphers: &[CipherSuite]) -> CipherCounts {
        let mut counts = CipherCounts {
            total: ciphers.len(),
            ..Default::default()
        };

        for cipher in ciphers {
            match cipher.strength() {
                CipherStrength::NULL => counts.null_ciphers += 1,
                CipherStrength::Export => counts.export_ciphers += 1,
                CipherStrength::Low => counts.low_strength += 1,
                CipherStrength::Medium => counts.medium_strength += 1,
                CipherStrength::High => counts.high_strength += 1,
            }

            if cipher.has_forward_secrecy() {
                counts.forward_secrecy += 1;
            }

            if cipher.is_aead() {
                counts.aead += 1;
            }
        }

        counts
    }

    pub async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>> {
        let mut results = HashMap::new();
        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let summary = self.test_protocol_ciphers(protocol).await?;
            if !summary.supported_ciphers.is_empty() {
                results.insert(protocol, summary);
            }
        }
        Ok(results)
    }

    pub async fn quick_test(&self, protocol: Protocol) -> Result<Vec<CipherSuite>> {
        let common_ciphers = CIPHER_DB.get_recommended_ciphers();
        let mut supported = Vec::new();

        for cipher in common_ciphers {
            if self.is_cipher_compatible_with_protocol(&cipher, protocol) {
                let result = self.test_single_cipher(&cipher, protocol).await?;
                if result.supported {
                    supported.push(cipher);
                }
            }
        }

        Ok(supported)
    }
}
