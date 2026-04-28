// Adaptive controller for dynamic timeouts, backoff, and concurrency.
//
// This module provides a lightweight feedback controller that adjusts
// connection timeouts, retry backoff, and concurrency based on observed
// network behavior (e.g., timeouts). It is intentionally conservative
// to avoid oscillations while improving resilience for slow or rate-limited hosts.
//
// NOTE: Uses std::sync::Mutex because all operations are very short (just reading/writing
// numeric values) and never cross await points. This is more efficient than tokio::sync::Mutex
// for this use case and avoids the need for async methods.

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Helper to lock mutex with poisoning recovery
/// Returns the guard, recovering from poisoning if necessary
pub fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            // Mutex is poisoned - recover the guard anyway (data is still valid)
            // The panic that caused poisoning already propagated its error
            tracing::warn!("Mutex poisoned, recovering with available data");
            poisoned.into_inner()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AdaptiveSnapshot {
    pub connect_timeout: Duration,
    pub socket_timeout: Duration,
    pub backoff: Duration,
    pub max_backoff: Duration,
    pub max_retries: usize,
    pub max_concurrency: usize,
}

#[derive(Debug)]
struct AdaptiveState {
    base_connect_timeout: Duration,
    base_socket_timeout: Duration,
    base_backoff: Duration,
    base_max_backoff: Duration,
    base_max_concurrency: usize,
    max_retries: usize,
    connect_timeout: Duration,
    socket_timeout: Duration,
    backoff: Duration,
    max_backoff: Duration,
    max_concurrency: usize,
    consecutive_timeouts: u32,
    consecutive_failures: u32,
    success_streak: u32,
}

#[derive(Clone, Debug)]
pub struct AdaptiveController {
    state: Arc<Mutex<AdaptiveState>>,
}

impl AdaptiveController {
    pub fn new(
        base_connect_timeout: Duration,
        base_socket_timeout: Duration,
        base_backoff: Duration,
        base_max_backoff: Duration,
        max_retries: usize,
        base_max_concurrency: usize,
    ) -> Self {
        let base_max_concurrency = base_max_concurrency.max(1);
        Self {
            state: Arc::new(Mutex::new(AdaptiveState {
                base_connect_timeout,
                base_socket_timeout,
                base_backoff,
                base_max_backoff,
                base_max_concurrency,
                max_retries,
                connect_timeout: base_connect_timeout,
                socket_timeout: base_socket_timeout,
                backoff: base_backoff,
                max_backoff: base_max_backoff,
                max_concurrency: base_max_concurrency,
                consecutive_timeouts: 0,
                consecutive_failures: 0,
                success_streak: 0,
            })),
        }
    }

    pub fn snapshot(&self) -> AdaptiveSnapshot {
        let state = lock_mutex(&self.state);
        AdaptiveSnapshot {
            connect_timeout: state.connect_timeout,
            socket_timeout: state.socket_timeout,
            backoff: state.backoff,
            max_backoff: state.max_backoff,
            max_retries: state.max_retries,
            max_concurrency: state.max_concurrency,
        }
    }

    pub fn connect_timeout(&self) -> Duration {
        self.snapshot().connect_timeout
    }

    pub fn socket_timeout(&self) -> Duration {
        self.snapshot().socket_timeout
    }

    pub fn backoff(&self) -> Duration {
        self.snapshot().backoff
    }

    pub fn max_backoff(&self) -> Duration {
        self.snapshot().max_backoff
    }

    pub fn max_retries(&self) -> usize {
        self.snapshot().max_retries
    }

    pub fn max_concurrency(&self) -> usize {
        self.snapshot().max_concurrency
    }

    pub fn on_timeout(&self) {
        let mut state = lock_mutex(&self.state);
        state.consecutive_timeouts = state.consecutive_timeouts.saturating_add(1);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.success_streak = 0;

        // Increase timeouts cautiously, cap at 4x base.
        state.connect_timeout = min_duration(
            add_duration(state.connect_timeout, Duration::from_secs(2)),
            mul_duration(state.base_connect_timeout, 4),
        );
        state.socket_timeout = min_duration(
            add_duration(state.socket_timeout, Duration::from_secs(2)),
            mul_duration(state.base_socket_timeout, 4),
        );

        // Increase backoff, expand max_backoff if needed (cap at 4x base).
        state.max_backoff = min_duration(
            mul_duration(state.max_backoff, 2),
            mul_duration(state.base_max_backoff, 4),
        );
        state.backoff = min_duration(mul_duration(state.backoff, 2), state.max_backoff);

        // Reduce concurrency on sustained timeouts.
        if state.consecutive_timeouts >= 2 {
            state.max_concurrency = (state.max_concurrency / 2).max(1);
        }
    }

    pub fn on_retryable_error(&self) {
        let mut state = lock_mutex(&self.state);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.success_streak = 0;

        // Mild backoff increase for non-timeout retriable errors.
        state.backoff = min_duration(
            add_duration(state.backoff, Duration::from_millis(50)),
            state.max_backoff,
        );

        // Nudge concurrency down slightly if errors persist.
        if state.consecutive_failures >= 3 {
            state.max_concurrency = (state.max_concurrency.saturating_sub(1)).max(1);
        }
    }

    pub fn on_non_retryable_error(&self) {
        let mut state = lock_mutex(&self.state);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.success_streak = 0;
    }

    pub fn on_success(&self) {
        let mut state = lock_mutex(&self.state);
        state.success_streak = state.success_streak.saturating_add(1);
        state.consecutive_timeouts = 0;
        state.consecutive_failures = 0;

        if state.success_streak < 5 {
            return;
        }

        // Gradually recover towards base settings.
        state.connect_timeout = max_duration(
            sub_duration(state.connect_timeout, Duration::from_secs(1)),
            state.base_connect_timeout,
        );
        state.socket_timeout = max_duration(
            sub_duration(state.socket_timeout, Duration::from_secs(1)),
            state.base_socket_timeout,
        );
        state.backoff = max_duration(div_duration(state.backoff, 2), state.base_backoff);
        state.max_backoff = max_duration(
            sub_duration(state.max_backoff, div_duration(state.base_max_backoff, 4)),
            state.base_max_backoff,
        );
        state.max_concurrency = (state.max_concurrency + 1).min(state.base_max_concurrency);

        state.success_streak = 0;
    }
}

fn add_duration(a: Duration, b: Duration) -> Duration {
    let sum = a.as_millis().saturating_add(b.as_millis());
    let capped = sum.min(u64::MAX as u128);
    Duration::from_millis(capped as u64)
}

fn sub_duration(a: Duration, b: Duration) -> Duration {
    // I3 fix: use nanosecond precision so sub-millisecond base values don't
    // truncate away. Previously `sub_duration(500µs, 0.5ms)` returned 0µs in
    // either direction because the millisecond conversion rounded both operands
    // down to 0.
    if a > b {
        Duration::from_nanos(a.as_nanos().saturating_sub(b.as_nanos()) as u64)
    } else {
        Duration::from_nanos(0)
    }
}

fn mul_duration(a: Duration, factor: u64) -> Duration {
    // Use nanosecond precision to stay consistent with sub/div helpers.
    let nanos = a.as_nanos();
    let result = nanos.saturating_mul(factor as u128);
    let capped = result.min(u64::MAX as u128);
    Duration::from_nanos(capped as u64)
}

fn div_duration(a: Duration, divisor: u64) -> Duration {
    if divisor == 0 {
        return a;
    }
    // I3 fix: divide in nanoseconds so bases under 4 ms don't collapse to 0.
    // Previously `div_duration(3ms, 4)` returned 0ms, making `on_success`
    // never converge `max_backoff` back to the base after a doubling sequence.
    Duration::from_nanos((a.as_nanos() / divisor as u128) as u64)
}

fn min_duration(a: Duration, b: Duration) -> Duration {
    if a <= b { a } else { b }
}

fn max_duration(a: Duration, b: Duration) -> Duration {
    if a >= b { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_timeouts_increase_on_timeout() {
        let controller = AdaptiveController::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(100),
            Duration::from_secs(2),
            3,
            10,
        );

        controller.on_timeout();
        let snapshot = controller.snapshot();
        assert!(snapshot.connect_timeout >= Duration::from_secs(5));
        assert!(snapshot.socket_timeout >= Duration::from_secs(5));
        assert!(snapshot.backoff >= Duration::from_millis(100));
    }

    #[test]
    fn test_adaptive_recovery_on_success() {
        let controller = AdaptiveController::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(100),
            Duration::from_secs(2),
            3,
            10,
        );

        controller.on_timeout();
        for _ in 0..5 {
            controller.on_success();
        }

        let snapshot = controller.snapshot();
        assert!(snapshot.connect_timeout <= Duration::from_secs(7));
        assert!(snapshot.max_concurrency >= 1);
    }

    #[test]
    fn test_concurrency_reduces_on_retries_and_timeouts() {
        let controller = AdaptiveController::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(100),
            Duration::from_secs(2),
            3,
            4,
        );

        controller.on_retryable_error();
        controller.on_retryable_error();
        controller.on_retryable_error();
        let snapshot = controller.snapshot();
        assert!(snapshot.max_concurrency <= 3);

        controller.on_timeout();
        controller.on_timeout();
        let snapshot = controller.snapshot();
        assert!(snapshot.max_concurrency <= 2);
    }

    #[test]
    fn test_duration_helpers_edge_cases() {
        let base = Duration::from_millis(250);
        assert_eq!(sub_duration(base, base), Duration::from_millis(0));
        assert_eq!(div_duration(base, 0), base);
        assert_eq!(
            min_duration(Duration::from_millis(5), Duration::from_millis(10)),
            Duration::from_millis(5)
        );
        assert_eq!(
            max_duration(Duration::from_millis(5), Duration::from_millis(10)),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn test_success_streak_below_threshold_no_recovery() {
        let controller = AdaptiveController::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(100),
            Duration::from_secs(2),
            3,
            6,
        );

        controller.on_timeout();
        for _ in 0..4 {
            controller.on_success();
        }

        let snapshot = controller.snapshot();
        assert!(snapshot.connect_timeout >= Duration::from_secs(6));
        assert!(snapshot.max_concurrency <= 6);
    }
}
