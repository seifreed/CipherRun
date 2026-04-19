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
    let alert_ratio = |responses: &[ServerResponse]| {
        responses.iter().filter(|r| r.alert_type.is_some()).count() as f64 / responses.len() as f64
    };
    let majority_has_alerts_a = alert_ratio(responses_a) > 0.5;
    let majority_has_alerts_b = alert_ratio(responses_b) > 0.5;
    if majority_has_alerts_a != majority_has_alerts_b {
        return true;
    }

    // Check for different alert types using proper categorical comparison
    let alert_types_a: std::collections::HashSet<u8> =
        responses_a.iter().filter_map(|r| r.alert_type).collect();
    let alert_types_b: std::collections::HashSet<u8> =
        responses_b.iter().filter_map(|r| r.alert_type).collect();

    // If both sets have alert types and they differ consistently, oracle exists
    if !alert_types_a.is_empty() && !alert_types_b.is_empty() {
        let dominant_a = find_dominant_alert_type(responses_a);
        let dominant_b = find_dominant_alert_type(responses_b);

        if let (Some(alert_a), Some(alert_b)) = (dominant_a, dominant_b)
            && alert_a != alert_b
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

    // Require difference > 2*stddev + 10ms minimum to account for jitter
    diff > 2.0 * combined_stddev + 10.0
}

/// Find the most common alert type in responses
pub(super) fn find_dominant_alert_type(responses: &[ServerResponse]) -> Option<u8> {
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
        .map(|(alert, _)| alert)
}
