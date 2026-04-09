//! Shared timing analysis utilities for vulnerability detection.
//!
//! Provides statistical tools for detecting timing oracles in TLS implementations.
//! Used by both POODLE (Sleeping POODLE variant) and Padding Oracle (CVE-2016-2107) testers.

/// A collection of timing samples with statistical computation.
#[derive(Debug, Clone)]
pub struct TimingSampleSet {
    samples: Vec<f64>,
}

/// Computed statistics for a set of timing samples.
#[derive(Debug, Clone)]
pub struct TimingStatistics {
    pub mean: f64,
    pub variance: f64,
    pub stddev: f64,
    pub coefficient_of_variation: f64,
    pub count: usize,
}

/// Configuration for timing oracle detection, allowing callers
/// to tune thresholds for their specific vulnerability test.
#[derive(Debug, Clone)]
pub struct TimingOracleConfig {
    /// Minimum number of samples required for reliable detection.
    pub min_samples: usize,
    /// Timing difference (ms) above which an oracle may be present.
    pub timing_threshold_ms: f64,
    /// Maximum coefficient of variation for timing to be considered reliable.
    pub cv_max: f64,
    /// Minimum threshold added to statistical significance check (ms).
    /// For some tests this equals `timing_threshold_ms`; for others it's lower.
    pub significance_base_ms: f64,
}

/// Result of a timing oracle detection analysis.
#[derive(Debug, Clone)]
pub struct TimingOracleResult {
    pub oracle_detected: bool,
    pub timing_reliable: bool,
    pub statistically_significant: bool,
    pub timing_diff_ms: f64,
    pub valid_stats: TimingStatistics,
    pub invalid_stats: TimingStatistics,
}

impl TimingSampleSet {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, sample: f64) {
        self.samples.push(sample);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Compute mean, variance, stddev, and coefficient of variation.
    /// Returns `None` if the sample set is empty.
    pub fn compute_statistics(&self) -> Option<TimingStatistics> {
        if self.samples.is_empty() {
            return None;
        }

        let count = self.samples.len();
        let mean = self.samples.iter().sum::<f64>() / count as f64;

        let variance = self.samples.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / count as f64;
        let stddev = variance.sqrt();

        let coefficient_of_variation = if mean > 0.0 { stddev / mean } else { f64::MAX };

        Some(TimingStatistics {
            mean,
            variance,
            stddev,
            coefficient_of_variation,
            count,
        })
    }
}

/// Analyze two sets of timing samples (valid vs invalid) to detect a timing oracle.
///
/// Uses statistical significance testing: the timing difference must exceed
/// `2 * combined_stddev + significance_base_ms` and the coefficient of variation
/// must be below `cv_max` for measurements to be considered reliable.
pub fn detect_timing_oracle(
    valid: &TimingSampleSet,
    invalid: &TimingSampleSet,
    config: &TimingOracleConfig,
) -> Option<TimingOracleResult> {
    let valid_stats = valid.compute_statistics()?;
    let invalid_stats = invalid.compute_statistics()?;

    let min_samples = valid_stats.count.min(invalid_stats.count);
    if min_samples < config.min_samples {
        return None;
    }

    let timing_diff = (valid_stats.mean - invalid_stats.mean).abs();

    let timing_reliable = valid_stats.coefficient_of_variation < config.cv_max
        && invalid_stats.coefficient_of_variation < config.cv_max;

    let combined_stddev = (valid_stats.variance + invalid_stats.variance).sqrt();
    let statistically_significant =
        timing_diff > 2.0 * combined_stddev + config.significance_base_ms;

    let exceeds_threshold = timing_diff > config.timing_threshold_ms;

    let oracle_detected = timing_reliable && exceeds_threshold && statistically_significant;

    Some(TimingOracleResult {
        oracle_detected,
        timing_reliable,
        statistically_significant,
        timing_diff_ms: timing_diff,
        valid_stats,
        invalid_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_sample_set() {
        let set = TimingSampleSet::with_capacity(10);
        assert!(set.compute_statistics().is_none());
        assert!(set.is_empty());
    }

    #[test]
    fn test_single_sample() {
        let mut set = TimingSampleSet::with_capacity(10);
        set.push(5.0);
        let stats = set.compute_statistics().unwrap();
        assert_eq!(stats.mean, 5.0);
        assert_eq!(stats.variance, 0.0);
        assert_eq!(stats.stddev, 0.0);
        assert_eq!(stats.count, 1);
    }

    #[test]
    fn test_known_statistics() {
        let mut set = TimingSampleSet::with_capacity(5);
        for v in [10.0, 20.0, 30.0, 40.0, 50.0] {
            set.push(v);
        }
        let stats = set.compute_statistics().unwrap();
        assert!((stats.mean - 30.0).abs() < 1e-10);
        assert!((stats.variance - 200.0).abs() < 1e-10);
        assert!((stats.stddev - 200.0_f64.sqrt()).abs() < 1e-10);
        assert_eq!(stats.count, 5);
    }

    #[test]
    fn test_detect_oracle_clear_difference() {
        let mut valid = TimingSampleSet::with_capacity(10);
        let mut invalid = TimingSampleSet::with_capacity(10);

        // Valid: consistently ~10ms, Invalid: consistently ~50ms
        for _ in 0..10 {
            valid.push(10.0);
            invalid.push(50.0);
        }

        let config = TimingOracleConfig {
            min_samples: 5,
            timing_threshold_ms: 15.0,
            cv_max: 0.5,
            significance_base_ms: 10.0,
        };

        let result = detect_timing_oracle(&valid, &invalid, &config).unwrap();
        assert!(result.oracle_detected);
        assert!(result.timing_reliable);
        assert!((result.timing_diff_ms - 40.0).abs() < 1e-10);
    }

    #[test]
    fn test_detect_oracle_no_difference() {
        let mut valid = TimingSampleSet::with_capacity(10);
        let mut invalid = TimingSampleSet::with_capacity(10);

        for _ in 0..10 {
            valid.push(10.0);
            invalid.push(10.5);
        }

        let config = TimingOracleConfig {
            min_samples: 5,
            timing_threshold_ms: 15.0,
            cv_max: 0.5,
            significance_base_ms: 10.0,
        };

        let result = detect_timing_oracle(&valid, &invalid, &config).unwrap();
        assert!(!result.oracle_detected);
    }

    #[test]
    fn test_detect_oracle_high_variance() {
        let mut valid = TimingSampleSet::with_capacity(10);
        let mut invalid = TimingSampleSet::with_capacity(10);

        // High variance data — CV will exceed threshold
        for v in [1.0, 100.0, 1.0, 100.0, 1.0, 100.0, 1.0, 100.0, 1.0, 100.0] {
            valid.push(v);
        }
        for v in [
            50.0, 150.0, 50.0, 150.0, 50.0, 150.0, 50.0, 150.0, 50.0, 150.0,
        ] {
            invalid.push(v);
        }

        let config = TimingOracleConfig {
            min_samples: 5,
            timing_threshold_ms: 15.0,
            cv_max: 0.5,
            significance_base_ms: 10.0,
        };

        let result = detect_timing_oracle(&valid, &invalid, &config).unwrap();
        assert!(!result.timing_reliable);
        assert!(!result.oracle_detected);
    }

    #[test]
    fn test_insufficient_samples_returns_none() {
        let mut valid = TimingSampleSet::with_capacity(10);
        let mut invalid = TimingSampleSet::with_capacity(10);

        for _ in 0..3 {
            valid.push(10.0);
            invalid.push(50.0);
        }

        let config = TimingOracleConfig {
            min_samples: 5,
            timing_threshold_ms: 15.0,
            cv_max: 0.5,
            significance_base_ms: 10.0,
        };

        assert!(detect_timing_oracle(&valid, &invalid, &config).is_none());
    }
}
