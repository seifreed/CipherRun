// Oracle detection for POODLE variant testing
//
// Statistical analysis of server responses to detect padding oracles
// via alert type differences or timing side channels.

use super::ServerResponse;

/// Detect if there's an observable oracle between two response sets
pub(super) fn detect_response_oracle(
    responses_a: &[ServerResponse],
    responses_b: &[ServerResponse],
) -> bool {
    const MIN_TIMING_SAMPLES: usize = 3;
    if responses_a.is_empty() || responses_b.is_empty() {
        return false;
    }

    // Require minimum samples before timing analysis to avoid stddev=0 false positives
    // (with 1 sample, variance=0 and any >10ms diff would trigger the timing oracle check)
    let enough_for_timing =
        responses_a.len() >= MIN_TIMING_SAMPLES && responses_b.len() >= MIN_TIMING_SAMPLES;

    // Asymmetric: one set consistently (majority) produces alerts and the other doesn't.
    // Using any() would trigger on a single noisy alert; require >50% for signal.
    //
    // V4 fix: also require MIN_TIMING_SAMPLES before evaluating the alert ratio.
    // With 1 response per set, ratio is 0/1=0 or 1/1=1, and a single alert flipping
    // the 0.5 boundary would trigger the oracle verdict on essentially no evidence.
    let enough_for_alert_ratio =
        responses_a.len() >= MIN_TIMING_SAMPLES && responses_b.len() >= MIN_TIMING_SAMPLES;
    let alert_ratio = |responses: &[ServerResponse]| {
        responses.iter().filter(|r| r.alert_type.is_some()).count() as f64 / responses.len() as f64
    };

    // A genuine response oracle (Zombie POODLE / GOLDENDOODLE) shows a CONSISTENT
    // difference, not a boundary flip caused by network noise (a dropped
    // connection registers as a missing alert). Require STRONG asymmetry: one
    // record type almost always alerts while the other almost never does.
    const STRONG_PRESENT: f64 = 0.8;
    const STRONG_ABSENT: f64 = 0.2;
    if enough_for_alert_ratio {
        let ratio_a = alert_ratio(responses_a);
        let ratio_b = alert_ratio(responses_b);
        if (ratio_a >= STRONG_PRESENT && ratio_b <= STRONG_ABSENT)
            || (ratio_b >= STRONG_PRESENT && ratio_a <= STRONG_ABSENT)
        {
            return true;
        }

        // Or both reliably alert, but with a CONSISTENTLY different alert type
        // (each clearly dominant within its own set). One stray differing alert
        // from noise must not flip the dominant type.
        if ratio_a >= STRONG_PRESENT
            && ratio_b >= STRONG_PRESENT
            && let (Some((alert_a, frac_a)), Some((alert_b, frac_b))) = (
                dominant_alert_with_fraction(responses_a),
                dominant_alert_with_fraction(responses_b),
            )
            && alert_a != alert_b
            && frac_a >= STRONG_PRESENT
            && frac_b >= STRONG_PRESENT
        {
            return true;
        }
    }

    // Check for timing differences as secondary indicator (requires sufficient samples)
    if !enough_for_timing {
        return false;
    }

    let avg_time_a =
        responses_a.iter().map(|r| r.response_time_ms).sum::<f64>() / responses_a.len() as f64;
    let avg_time_b =
        responses_b.iter().map(|r| r.response_time_ms).sum::<f64>() / responses_b.len() as f64;

    // Apply basic statistical controls to avoid false positives from network jitter
    let variance_a: f64 = responses_a
        .iter()
        .map(|r| (r.response_time_ms - avg_time_a).powi(2))
        .sum::<f64>()
        / (responses_a.len() as f64 - 1.0).max(1.0);
    let variance_b: f64 = responses_b
        .iter()
        .map(|r| (r.response_time_ms - avg_time_b).powi(2))
        .sum::<f64>()
        / (responses_b.len() as f64 - 1.0).max(1.0);
    let combined_stddev = (variance_a / (responses_a.len() as f64).max(1.0)
        + variance_b / (responses_b.len() as f64).max(1.0))
    .sqrt();
    let diff = (avg_time_a - avg_time_b).abs();

    // Timing is only a weak secondary indicator for a *response*-content oracle,
    // and remote timing is jitter-prone, so demand a very strong signal
    // (> 3*stddev + 50ms) before it alone declares an oracle. Genuine
    // Zombie/GOLDENDOODLE oracles are caught above by the alert-content checks.
    diff > 3.0 * combined_stddev + 50.0
}

/// Return the most common alert type and the fraction of responses carrying it.
fn dominant_alert_with_fraction(responses: &[ServerResponse]) -> Option<(u8, f64)> {
    use std::collections::HashMap;
    let mut counts: HashMap<u8, usize> = HashMap::new();
    for response in responses {
        if let Some(alert) = response.alert_type {
            *counts.entry(alert).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(alert, count)| (alert, count as f64 / responses.len() as f64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(alert: Option<u8>, time_ms: f64) -> ServerResponse {
        ServerResponse {
            connection_accepted: true,
            alert_type: alert,
            response_time_ms: time_ms,
            shows_differential_behavior: false,
        }
    }

    #[test]
    fn test_oracle_detection_requires_min_samples_for_alert_ratio() {
        // Regression test for V4: with one response per set the alert_ratio is
        // either 0.0 or 1.0. Previously the boolean difference alone triggered
        // a positive oracle verdict — now we require MIN_TIMING_SAMPLES (3).
        let a = vec![response(Some(21), 10.0)]; // alert
        let b = vec![response(None, 10.0)]; // no alert
        assert!(
            !detect_response_oracle(&a, &b),
            "1 sample per set must not be enough to claim an oracle"
        );
    }

    #[test]
    fn test_oracle_detection_alert_ratio_fires_with_enough_samples() {
        // 3 alerts vs 3 non-alerts → majority differs → oracle detected.
        let a: Vec<_> = (0..3).map(|_| response(Some(21), 10.0)).collect();
        let b: Vec<_> = (0..3).map(|_| response(None, 10.0)).collect();
        assert!(detect_response_oracle(&a, &b));
    }

    #[test]
    fn test_oracle_detection_ignores_empty_sets() {
        let a = vec![response(Some(21), 10.0)];
        let b: Vec<ServerResponse> = Vec::new();
        assert!(!detect_response_oracle(&a, &b));
    }
}
