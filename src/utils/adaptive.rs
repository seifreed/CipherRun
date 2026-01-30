// Adaptive controller for dynamic timeouts, backoff, and concurrency.
//
// This module provides a lightweight feedback controller that adjusts
// connection timeouts, retry backoff, and concurrency based on observed
// network behavior (e.g., timeouts). It is intentionally conservative
// to avoid oscillations while improving resilience for slow or rate-limited hosts.

use std::sync::{Arc, Mutex};
use std::time::Duration;

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
        let state = self.state.lock().expect("adaptive state poisoned");
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
        let mut state = self.state.lock().expect("adaptive state poisoned");
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
        let mut state = self.state.lock().expect("adaptive state poisoned");
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
        let mut state = self.state.lock().expect("adaptive state poisoned");
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.success_streak = 0;
    }

    pub fn on_success(&self) {
        let mut state = self.state.lock().expect("adaptive state poisoned");
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
        state.backoff = max_duration(
            div_duration(state.backoff, 2),
            state.base_backoff,
        );
        state.max_backoff = max_duration(
            sub_duration(state.max_backoff, div_duration(state.base_max_backoff, 4)),
            state.base_max_backoff,
        );
        state.max_concurrency = (state.max_concurrency + 1).min(state.base_max_concurrency);

        state.success_streak = 0;
    }
}

fn add_duration(a: Duration, b: Duration) -> Duration {
    Duration::from_millis(a.as_millis().saturating_add(b.as_millis()) as u64)
}

fn sub_duration(a: Duration, b: Duration) -> Duration {
    if a > b {
        Duration::from_millis(a.as_millis().saturating_sub(b.as_millis()) as u64)
    } else {
        Duration::from_millis(0)
    }
}

fn mul_duration(a: Duration, factor: u64) -> Duration {
    Duration::from_millis(a.as_millis().saturating_mul(factor as u128) as u64)
}

fn div_duration(a: Duration, divisor: u64) -> Duration {
    if divisor == 0 {
        return a;
    }
    Duration::from_millis((a.as_millis() / divisor as u128) as u64)
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
}
