// Cipher Tester - Tests which cipher suites are supported by the server

use super::{CipherStrength, CipherSuite};
use crate::Result;
use crate::data::CIPHER_DB;
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use crate::utils::network::Target;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use serde::{Deserialize, Serialize};

/// Result of cipher testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherTestResult {
    pub cipher: CipherSuite,
    pub supported: bool,
    pub protocol: Protocol,
    pub server_preference: Option<usize>, // Position in server's preference list
    pub handshake_time_ms: Option<u64>,
}

/// Cipher testing summary for a protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCipherSummary {
    pub protocol: Protocol,
    pub supported_ciphers: Vec<CipherSuite>,
    pub server_ordered: bool,
    pub server_preference: Vec<String>, // Ordered list of cipher hexcodes
    pub preferred_cipher: Option<CipherSuite>,
    pub counts: CipherCounts,
    pub avg_handshake_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherCounts {
    pub total: usize,
    pub null_ciphers: usize,
    pub export_ciphers: usize,
    pub low_strength: usize,
    pub medium_strength: usize,
    pub high_strength: usize,
    pub forward_secrecy: usize,
    pub aead: usize,
}

/// Cipher testing configuration
pub struct CipherTester {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    test_all_ciphers: bool,
    sleep_duration: Option<Duration>,
    use_rdp: bool,
    starttls_protocol: Option<crate::starttls::StarttlsProtocol>,
    test_all_ips: bool,
    retry_config: Option<crate::utils::retry::RetryConfig>,
    max_concurrent_tests: usize,
}

impl CipherTester {
    /// Create new cipher tester
    pub fn new(target: Target) -> Self {
        // Auto-detect RDP based on port
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(3), // Reduced from 5s to 3s for faster failure detection
            test_all_ciphers: false,
            sleep_duration: None,
            use_rdp,
            starttls_protocol: None,
            test_all_ips: false,
            retry_config: None,
            max_concurrent_tests: 10, // Default to 10 concurrent cipher tests
        }
    }

    /// Set connect timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set read timeout
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Enable testing all ciphers (slower but comprehensive)
    pub fn test_all(mut self, enable: bool) -> Self {
        self.test_all_ciphers = enable;
        self
    }

    /// Set sleep duration between connections
    pub fn with_sleep(mut self, duration: Duration) -> Self {
        self.sleep_duration = Some(duration);
        self
    }

    /// Enable or disable RDP mode
    pub fn with_rdp(mut self, enable: bool) -> Self {
        self.use_rdp = enable;
        self
    }

    /// Set STARTTLS protocol
    pub fn with_starttls(mut self, protocol: Option<crate::starttls::StarttlsProtocol>) -> Self {
        self.starttls_protocol = protocol;
        self
    }

    /// Enable testing all resolved IP addresses (for Anycast pools)
    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    /// Set retry configuration for handling transient network failures
    pub fn with_retry_config(mut self, config: Option<crate::utils::retry::RetryConfig>) -> Self {
        self.retry_config = config;
        self
    }

    /// Set maximum concurrent cipher tests
    pub fn with_max_concurrent_tests(mut self, max: usize) -> Self {
        self.max_concurrent_tests = max.max(1); // Ensure at least 1
        self
    }

    /// Test all cipher suites for a specific protocol
    pub async fn test_protocol_ciphers(&self, protocol: Protocol) -> Result<ProtocolCipherSummary> {
        let ciphers = if self.test_all_ciphers {
            CIPHER_DB.get_all_ciphers()
        } else {
            // Test common/recommended ciphers only for speed
            CIPHER_DB.get_recommended_ciphers()
        };

        // Filter compatible ciphers for this protocol
        let compatible_ciphers: Vec<CipherSuite> = ciphers
            .into_iter()
            .filter(|c| self.is_cipher_compatible_with_protocol(c, protocol))
            .collect();

        tracing::debug!(
            "Testing {} compatible ciphers for {:?} with max {} concurrent connections",
            compatible_ciphers.len(),
            protocol,
            self.max_concurrent_tests
        );

        // Create semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_tests));

        // Create arc for self to share across tasks
        let tester = Arc::new(self);

        // Test ciphers concurrently using futures stream with adaptive backoff
        let mut results: Vec<CipherTestResult> = Vec::new();
        let mut enetdown_count = 0;
        let mut current_batch_size = self.max_concurrent_tests;
        let mut cipher_queue: Vec<CipherSuite> = compatible_ciphers;
        let mut retry_queue: Vec<CipherSuite> = Vec::new();
        let max_enetdown_retries = 3;
        let mut retry_round = 0;
        
        // Process ciphers in batches with adaptive concurrency and retry
        while !cipher_queue.is_empty() || !retry_queue.is_empty() {
            // Switch to retry queue if main queue is empty
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
                // Longer backoff between retry rounds
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            
            // Get next batch of ciphers
            let batch_size = current_batch_size * 5;
            let batch: Vec<_> = cipher_queue.drain(..cipher_queue.len().min(batch_size)).collect();
            
            if batch.is_empty() {
                break;
            }
            
            // Test batch with current concurrency level
            let batch_results: Vec<(CipherSuite, Result<CipherTestResult>)> = stream::iter(batch)
                .map(|cipher| {
                    let sem = semaphore.clone();
                    let tester_clone = tester.clone();
                    let cipher_clone = cipher.clone();
                    async move {
                        // Acquire semaphore permit
                        let _permit = sem.acquire().await.expect("semaphore closed");

                        // Test the cipher
                        let result = tester_clone.test_single_cipher(&cipher, protocol).await;

                        // Sleep between requests if configured
                        if let Some(sleep_dur) = tester_clone.sleep_duration {
                            tokio::time::sleep(sleep_dur).await;
                        }

                        (cipher_clone, result)
                    }
                })
                .buffer_unordered(current_batch_size)
                .collect::<Vec<_>>()
                .await;
            
            // Check for ENETDOWN errors and adapt concurrency
            let mut batch_enetdown = 0;
            let mut batch_other_errors = 0;
            
            // Collect results, queueing ENETDOWN failures for retry
            for (cipher, result) in batch_results {
                match result {
                    Ok(test_result) => {
                        results.push(test_result);
                    }
                    Err(e) => {
                        let err_msg = e.to_string().to_lowercase();
                        if err_msg.contains("network is down") || err_msg.contains("os error 50") {
                            // ENETDOWN error - queue for retry with reduced concurrency
                            batch_enetdown += 1;
                            retry_queue.push(cipher);
                        } else {
                            // Other error - log and continue (treat as unsupported)
                            batch_other_errors += 1;
                            tracing::debug!("Cipher test error (non-ENETDOWN): {}", e);
                        }
                    }
                }
            }
            
            enetdown_count += batch_enetdown;
            
            // Adaptive backoff: if we hit ENETDOWN errors, reduce concurrency aggressively
            if batch_enetdown > 0 {
                let old_size = current_batch_size;
                // More aggressive reduction if many errors
                if batch_enetdown > current_batch_size / 2 {
                    current_batch_size = (current_batch_size / 3).max(1);
                } else {
                    current_batch_size = (current_batch_size / 2).max(1);
                }
                tracing::warn!(
                    "Detected {} ENETDOWN error(s), reducing concurrency from {} to {} and adding backoff",
                    batch_enetdown,
                    old_size,
                    current_batch_size
                );
                // Longer backoff delay to let the network stack recover
                let backoff_secs = if batch_enetdown > 10 { 8 } else { 5 };
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
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

        // Extract supported ciphers
        let supported: Vec<CipherSuite> = results
            .iter()
            .filter(|r| r.supported)
            .map(|r| r.cipher.clone())
            .collect();

        tracing::debug!(
            "Found {} supported ciphers out of {} tested for {:?}",
            supported.len(),
            results.len(),
            protocol
        );

        // Determine server cipher preference order
        let server_preference = self
            .determine_server_preference(protocol, &supported)
            .await?;
        let server_ordered = !server_preference.is_empty();

        // Get preferred cipher (first in server's preference list)
        let preferred_cipher = if !server_preference.is_empty() {
            CIPHER_DB.get_by_hexcode(&server_preference[0])
        } else {
            supported.first().cloned()
        };

        // Calculate statistics
        let counts = self.calculate_cipher_counts(&supported);

        // Calculate average handshake time
        let handshake_times: Vec<u64> =
            results.iter().filter_map(|r| r.handshake_time_ms).collect();
        let avg_handshake_time_ms = if !handshake_times.is_empty() {
            Some(handshake_times.iter().sum::<u64>() / handshake_times.len() as u64)
        } else {
            None
        };

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

    /// Test a single cipher suite
    pub async fn test_single_cipher(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
    ) -> Result<CipherTestResult> {
        // Parse hexcode - skip if it doesn't fit in u16
        let hexcode = match u16::from_str_radix(&cipher.hexcode, 16) {
            Ok(h) => h,
            Err(_) => {
                // Hexcode too large for u16, mark as unsupported
                return Ok(CipherTestResult {
                    cipher: cipher.clone(),
                    supported: false,
                    protocol,
                    server_preference: None,
                    handshake_time_ms: None,
                });
            }
        };

        let start = std::time::Instant::now();
        let supported = self.try_cipher_handshake(protocol, hexcode).await?;
        let handshake_time_ms = if supported {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        Ok(CipherTestResult {
            cipher: cipher.clone(),
            supported,
            protocol,
            server_preference: None, // Will be determined later
            handshake_time_ms,
        })
    }

    /// Attempt TLS handshake with specific cipher
    async fn try_cipher_handshake(&self, protocol: Protocol, cipher_hexcode: u16) -> Result<bool> {
        if self.test_all_ips {
            // Test all IPs and return true only if ALL support the cipher
            self.try_cipher_handshake_all_ips(protocol, cipher_hexcode)
                .await
        } else {
            // Test only first IP (default behavior)
            let addr = self.target.socket_addrs()[0];
            self.try_cipher_handshake_on_ip(protocol, cipher_hexcode, addr)
                .await
        }
    }

    /// Test cipher on all IPs
    async fn try_cipher_handshake_all_ips(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
    ) -> Result<bool> {
        let addrs = self.target.socket_addrs();

        if addrs.is_empty() {
            return Ok(false);
        }

        let mut all_support = true;

        for addr in &addrs {
            let ip_supports = self
                .try_cipher_handshake_on_ip(protocol, cipher_hexcode, *addr)
                .await?;
            if !ip_supports {
                all_support = false;
                break; // Early exit for performance
            }
        }

        Ok(all_support)
    }

    /// Attempt TLS handshake with specific cipher on specific IP
    async fn try_cipher_handshake_on_ip(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
        addr: std::net::SocketAddr,
    ) -> Result<bool> {
        // Connect TCP with retry logic
        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        // Send RDP preamble if needed
        if self.use_rdp
            && let Err(_) = crate::protocols::rdp::RdpPreamble::send(&mut stream).await
        {
            return Ok(false);
        }

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(false);
            }
        }

        // Build ClientHello with only this cipher
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_cipher(cipher_hexcode);

        // Add SNI and basic extensions
        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send ClientHello and read response
        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            // Read ServerHello or Alert
            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await?;

            if n == 0 {
                return Ok(false);
            }

            // Check if we got ServerHello (0x16 = Handshake, 0x02 = ServerHello)
            if n >= 6 && response[0] == 0x16 {
                // Look for ServerHello message
                if n > 5 && response[5] == 0x02 {
                    return Ok(true);
                }
            }

            // Check for Alert (0x15)
            if response[0] == 0x15 {
                return Ok(false);
            }

            Ok(false)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(false), // Timeout
        }
    }

    /// Determine server's cipher preference order
    async fn determine_server_preference(
        &self,
        protocol: Protocol,
        supported_ciphers: &[CipherSuite],
    ) -> Result<Vec<String>> {
        if supported_ciphers.is_empty() {
            return Ok(Vec::new());
        }

        let mut preference_order = Vec::new();

        // Send ClientHello with all supported ciphers in different orders
        // and see if server always picks the same one (server preference)
        // or picks our first one (client preference)

        let cipher_hexcodes: Vec<u16> = supported_ciphers
            .iter()
            .filter_map(|c| u16::from_str_radix(&c.hexcode, 16).ok())
            .collect();

        if cipher_hexcodes.len() < 2 {
            // Not enough ciphers to determine preference
            return Ok(supported_ciphers
                .iter()
                .map(|c| c.hexcode.clone())
                .collect());
        }

        // Test 1: Send ciphers in original order
        let first_choice = self
            .get_server_chosen_cipher(protocol, &cipher_hexcodes)
            .await?;

        tracing::debug!(
            "Cipher preference test 1 (original order): client offered {:04x?}, server chose {:04x?}",
            cipher_hexcodes,
            first_choice
        );

        // Test 2: Send ciphers in reverse order
        let mut reversed = cipher_hexcodes.clone();
        reversed.reverse();
        let second_choice = self.get_server_chosen_cipher(protocol, &reversed).await?;

        tracing::debug!(
            "Cipher preference test 2 (reversed order): client offered {:04x?}, server chose {:04x?}",
            reversed,
            second_choice
        );

        // Perform additional test if we have 3 or more ciphers for better accuracy
        let (third_choice, third_offered) = if cipher_hexcodes.len() >= 3 {
            // Test 3: Send ciphers in a different order (move last to first)
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

        // Analyze results
        // Check if server is following client's first choice (client preference)
        // or always picking the same cipher regardless of order (server preference)
        let client_follows_first = if let Some(first) = first_choice {
            cipher_hexcodes.first() == Some(&first)
        } else {
            false
        };

        let client_follows_first_reversed = if let Some(second) = second_choice {
            reversed.first() == Some(&second)
        } else {
            false
        };

        let client_follows_first_rotated = match (&third_choice, &third_offered) {
            (Some(third), Some(offered)) => offered.first() == Some(third),
            _ => false,
        };

        // If server is consistently picking the first cipher from client's list, it's client preference
        let is_client_preference = client_follows_first
            && client_follows_first_reversed
            && (third_choice.is_none() || client_follows_first_rotated);

        // Check if server always picks the same cipher (strongest evidence of server preference)
        let all_same = if let Some(third) = third_choice {
            // With 3 tests, check if all choices are the same
            first_choice == second_choice && second_choice == Some(third)
        } else {
            // With 2 tests, check if both choices are the same
            first_choice == second_choice
        };

        // Check if server picks the same cipher in at least 2 out of 3 tests
        // AND that cipher appears in different positions in the client lists
        // This indicates server preference even if one test resulted in a different choice
        let mostly_same = if let (Some(second), Some(third)) = (second_choice, third_choice) {
            if second == third {
                // Tests 2 and 3 chose the same cipher
                // Check if this cipher was in different positions in client lists
                let pos_in_test2 = reversed.iter().position(|&c| c == second);
                let pos_in_test3 = third_offered
                    .as_ref()
                    .and_then(|offered| offered.iter().position(|&c| c == second));

                // If the cipher was in different positions but still chosen, it's server preference
                if let (Some(pos2), Some(pos3)) = (pos_in_test2, pos_in_test3) {
                    pos2 != pos3
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Determine final result
        let final_server_has_preference = if is_client_preference {
            tracing::debug!(
                "Server respects client cipher preference (consistently picks client's first choice)"
            );
            false
        } else if all_same {
            tracing::debug!("Server enforces cipher preference (chose same cipher in all tests)");
            true
        } else if mostly_same {
            tracing::debug!(
                "Server enforces cipher preference (chose same cipher in multiple tests from different positions)"
            );
            true
        } else {
            // Mixed behavior - default to assuming server preference for security
            tracing::debug!(
                "Server cipher preference unclear (mixed behavior detected, assuming server preference)"
            );
            true
        };

        if final_server_has_preference {
            // Server has preference (always picks the same cipher)
            if let Some(chosen) = first_choice {
                preference_order.push(format!("{:04x}", chosen));

                // Find remaining ciphers in preference order
                for cipher in supported_ciphers {
                    let hex = cipher.hexcode.clone();
                    if !preference_order.contains(&hex) {
                        preference_order.push(hex);
                    }
                }
            }
        } else {
            // Client preference (server picks different ciphers based on client order)
            // Return empty to indicate client preference
            return Ok(Vec::new());
        }

        Ok(preference_order)
    }

    /// Get the cipher that the server chooses from a list
    async fn get_server_chosen_cipher(
        &self,
        protocol: Protocol,
        cipher_hexcodes: &[u16],
    ) -> Result<Option<u16>> {
        // For cipher preference detection, we only need to test one IP
        // Use first IP regardless of test_all_ips flag
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

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(None);
            }
        }

        // Build ClientHello with all these ciphers
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(cipher_hexcodes);
        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send and read ServerHello
        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await?;

            if n >= 44 && response[0] == 0x16 && response[5] == 0x02 {
                // Parse chosen cipher from ServerHello
                // ServerHello structure:
                // 5 bytes: Record header
                // 4 bytes: Handshake header
                // 2 bytes: Server version
                // 32 bytes: Random
                // 1 byte: Session ID length
                // N bytes: Session ID
                // 2 bytes: Cipher suite <-- what we want

                let session_id_len = response[43] as usize;
                let cipher_offset = 44 + session_id_len;

                tracing::debug!(
                    "ServerHello: session_id_len={}, cipher_offset={}, response_len={}",
                    session_id_len,
                    cipher_offset,
                    n
                );

                if n >= cipher_offset + 2 {
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

    /// Check if cipher is compatible with protocol
    fn is_cipher_compatible_with_protocol(&self, cipher: &CipherSuite, protocol: Protocol) -> bool {
        // TLS 1.3 has its own cipher suites
        if matches!(protocol, Protocol::TLS13) {
            return cipher.protocol.contains("TLS13") || cipher.protocol.contains("TLSv1.3");
        }

        // SSLv2 has specific cipher format
        if matches!(protocol, Protocol::SSLv2) {
            return cipher.protocol.contains("SSLv2");
        }

        // SSLv3/TLS 1.0-1.2 share most ciphers
        // Exclude TLS 1.3 specific ciphers
        !cipher.protocol.contains("TLS13") && !cipher.protocol.contains("SSLv2")
    }

    /// Calculate cipher statistics
    fn calculate_cipher_counts(&self, ciphers: &[CipherSuite]) -> CipherCounts {
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

    /// Test all protocols and their ciphers
    pub async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>> {
        let mut results = HashMap::new();

        for protocol in Protocol::all() {
            // Skip QUIC for now
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

    /// Quick test - only test for cipher suite support, not order
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_cipher_detection() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = CipherTester::new(target);

        let summary = tester.test_protocol_ciphers(Protocol::TLS12).await.unwrap();

        // Should support at least some ciphers
        assert!(!summary.supported_ciphers.is_empty());

        // Should have forward secrecy ciphers
        assert!(summary.counts.forward_secrecy > 0);

        // Should not support NULL or EXPORT ciphers
        assert_eq!(summary.counts.null_ciphers, 0);
        assert_eq!(summary.counts.export_ciphers, 0);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_server_preference() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = CipherTester::new(target);

        let summary = tester.test_protocol_ciphers(Protocol::TLS12).await.unwrap();

        // Google should have server cipher preference
        assert!(summary.server_ordered);
        assert!(!summary.server_preference.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_quick_scan() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = CipherTester::new(target);

        let ciphers = tester.quick_test(Protocol::TLS12).await.unwrap();

        assert!(!ciphers.is_empty());
    }

    #[test]
    fn test_cipher_strength_calculation() {
        let cipher = CipherSuite {
            hexcode: "c030".to_string(),
            openssl_name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            iana_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES256-GCM".to_string(),
            mac: "SHA384".to_string(),
            bits: 256,
            export: false,
        };

        assert_eq!(cipher.strength(), CipherStrength::High);
        assert!(cipher.has_forward_secrecy());
        assert!(cipher.is_aead());
    }
}
