// Certificate Deduplicator using Bloom Filter
//
// Memory-efficient deduplication for certificate streaming

use bloomfilter::Bloom;
use sha2::{Digest, Sha256};

/// Deduplicator using Bloom filter for memory-efficient duplicate detection
pub struct Deduplicator {
    bloom: Bloom<[u8; 32]>,
    total_seen: u64,
    duplicates_filtered: u64,
}

impl Deduplicator {
    /// Create a new deduplicator
    ///
    /// # Arguments
    /// * `expected_items` - Expected number of unique items (used for sizing)
    /// * `false_positive_rate` - Acceptable false positive rate (e.g., 0.0001 for 0.01%)
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let bloom = Bloom::new_for_fp_rate(expected_items, false_positive_rate);

        Self {
            bloom,
            total_seen: 0,
            duplicates_filtered: 0,
        }
    }

    /// Check if certificate has been seen before and mark it as seen
    ///
    /// Returns true if this is a new (unique) certificate
    pub fn check_and_insert(&mut self, cert_der: &[u8]) -> bool {
        self.total_seen += 1;

        // Hash the certificate DER to get a consistent key
        let hash = self.hash_certificate(cert_der);

        // Check if we've seen this hash before
        if self.bloom.check(&hash) {
            // Likely a duplicate (subject to false positive rate)
            self.duplicates_filtered += 1;
            false
        } else {
            // New certificate - insert into bloom filter
            self.bloom.set(&hash);
            true
        }
    }

    /// Hash a certificate to create a bloom filter key
    fn hash_certificate(&self, cert_der: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        hasher.finalize().into()
    }

    /// Get total certificates seen
    pub fn total_seen(&self) -> u64 {
        self.total_seen
    }

    /// Get total duplicates filtered
    pub fn duplicates_filtered(&self) -> u64 {
        self.duplicates_filtered
    }

    /// Get unique certificates count
    pub fn unique_count(&self) -> u64 {
        self.total_seen - self.duplicates_filtered
    }

    /// Get current false positive rate estimate
    pub fn false_positive_rate(&self) -> f64 {
        // Bloom filter false positive rate increases with number of items
        // This is an approximation based on the expected formula:
        // (1 - e^(-kn/m))^k
        // where k = number of hash functions, n = number of items, m = bit array size

        // For simplicity, we'll return the configured rate
        // In practice, the actual rate will be close to this for expected_items
        let bitmap_bits = self.bloom.number_of_bits() as f64;
        let num_hashes = self.bloom.number_of_hash_functions() as f64;
        let items_inserted = self.unique_count() as f64;

        if items_inserted == 0.0 {
            return 0.0;
        }

        let exponent = -(num_hashes * items_inserted) / bitmap_bits;
        let base = 1.0 - exponent.exp();
        base.powf(num_hashes)
    }

    /// Get memory usage estimate in bytes
    pub fn memory_usage_bytes(&self) -> usize {
        // Bloom filter bitmap size + struct overhead
        ((self.bloom.number_of_bits() / 8) as usize) + std::mem::size_of::<Self>()
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        // Default: 1 million expected items with 0.01% false positive rate
        Self::new(1_000_000, 0.0001)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicator_new_certificates() {
        let mut dedup = Deduplicator::new(1000, 0.01);

        let cert1 = b"certificate data 1";
        let cert2 = b"certificate data 2";

        // First time seeing cert1 - should be unique
        assert!(dedup.check_and_insert(cert1));
        assert_eq!(dedup.total_seen(), 1);
        assert_eq!(dedup.unique_count(), 1);
        assert_eq!(dedup.duplicates_filtered(), 0);

        // First time seeing cert2 - should be unique
        assert!(dedup.check_and_insert(cert2));
        assert_eq!(dedup.total_seen(), 2);
        assert_eq!(dedup.unique_count(), 2);
        assert_eq!(dedup.duplicates_filtered(), 0);
    }

    #[test]
    fn test_deduplicator_duplicate_certificates() {
        let mut dedup = Deduplicator::new(1000, 0.01);

        let cert1 = b"certificate data 1";

        // First time - unique
        assert!(dedup.check_and_insert(cert1));
        assert_eq!(dedup.unique_count(), 1);

        // Second time - duplicate
        assert!(!dedup.check_and_insert(cert1));
        assert_eq!(dedup.total_seen(), 2);
        assert_eq!(dedup.unique_count(), 1);
        assert_eq!(dedup.duplicates_filtered(), 1);

        // Third time - still duplicate
        assert!(!dedup.check_and_insert(cert1));
        assert_eq!(dedup.total_seen(), 3);
        assert_eq!(dedup.unique_count(), 1);
        assert_eq!(dedup.duplicates_filtered(), 2);
    }

    #[test]
    fn test_deduplicator_memory_usage() {
        let dedup = Deduplicator::new(1000, 0.01);
        let memory = dedup.memory_usage_bytes();

        // Should use some memory (at least a few KB for 1000 items)
        assert!(memory > 1000);

        // Should use reasonable memory (less than 1 MB for 1000 items)
        assert!(memory < 1_000_000);
    }

    #[test]
    fn test_deduplicator_false_positive_rate() {
        let dedup = Deduplicator::new(1000, 0.01);
        let fp_rate = dedup.false_positive_rate();

        // Initial FP rate should be very low (no items inserted)
        assert!(fp_rate >= 0.0);
        assert!(fp_rate <= 1.0);
    }

    #[test]
    fn test_deduplicator_different_certificates() {
        let mut dedup = Deduplicator::new(100, 0.01);

        // Generate 50 different certificates
        let mut unique_inserted = 0u64;
        for i in 0..50 {
            let cert = format!("certificate data {}", i);
            if dedup.check_and_insert(cert.as_bytes()) {
                unique_inserted += 1;
            }
        }

        assert_eq!(dedup.total_seen(), 50);
        // Bloom filter can yield false positives; allow small tolerance.
        assert!(unique_inserted >= 45);
        assert!(dedup.unique_count() <= 50);
    }

    #[test]
    fn test_deduplicator_hash_consistency() {
        let dedup = Deduplicator::new(100, 0.01);

        let cert = b"test certificate";
        let hash1 = dedup.hash_certificate(cert);
        let hash2 = dedup.hash_certificate(cert);

        // Same certificate should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }
}
