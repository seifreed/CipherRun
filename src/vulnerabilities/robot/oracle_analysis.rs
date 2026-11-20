use super::{RobotStatus, alert_signal};

const MIN_BYTE_DIFFERENCES: usize = 4;
const MIN_RELATIVE_DIFFERENCE: f64 = 0.1;
const PATTERN_PREFIX_LEN: usize = 32;

pub(super) fn classify_responses(
    successful_responses: &[&Vec<u8>],
    per_vector: &[Vec<Vec<u8>>],
    confirmation_rounds: usize,
) -> RobotStatus {
    match alert_signal::classify(per_vector, confirmation_rounds) {
        alert_signal::CodeSignal::ConfirmedOracle => return RobotStatus::Vulnerable,
        alert_signal::CodeSignal::Inconclusive => return RobotStatus::Inconclusive,
        alert_signal::CodeSignal::None => {}
    }

    let response_patterns = response_patterns(successful_responses);
    if response_patterns.len() < 2 {
        return RobotStatus::NotVulnerable;
    }

    classify_pattern_divergence(&response_patterns)
}

fn response_patterns(successful_responses: &[&Vec<u8>]) -> std::collections::BTreeSet<Vec<u8>> {
    successful_responses
        .iter()
        .filter_map(|response| {
            let pattern_len = response.len().min(PATTERN_PREFIX_LEN);
            response.get(..pattern_len).map(Vec::from)
        })
        .collect()
}

fn classify_pattern_divergence(
    response_patterns: &std::collections::BTreeSet<Vec<u8>>,
) -> RobotStatus {
    let patterns: Vec<_> = response_patterns.iter().collect();
    let Some((left, right)) = most_divergent_pair(&patterns) else {
        return RobotStatus::Inconclusive;
    };

    let content_differences = content_difference_count(left, right);
    let len_difference = left.len().abs_diff(right.len());
    let byte_differences = content_differences + len_difference;

    if content_differences == 0 && len_difference > 0 {
        tracing::debug!(
            event_name = "vulnerability.robot.response_divergence",
            response_pattern_count = response_patterns.len(),
            content_byte_differences = content_differences,
            length_difference = len_difference,
            outcome = "length_only_noise",
            "ROBOT response patterns differ only by length"
        );
        return RobotStatus::NotVulnerable;
    }

    let pattern_len = left.len().max(right.len());
    let relative_diff = if pattern_len > 0 {
        byte_differences as f64 / pattern_len as f64
    } else {
        0.0
    };

    if byte_differences >= MIN_BYTE_DIFFERENCES || relative_diff >= MIN_RELATIVE_DIFFERENCE {
        tracing::debug!(
            event_name = "vulnerability.robot.response_divergence",
            response_pattern_count = response_patterns.len(),
            byte_differences,
            relative_difference_percent = relative_diff * 100.0,
            pattern_length = pattern_len,
            outcome = "weak_oracle",
            "ROBOT response patterns diverged"
        );
        return RobotStatus::WeakOracle;
    }

    if byte_differences >= 2 {
        tracing::info!(
            event_name = "vulnerability.robot.response_divergence",
            byte_differences,
            relative_difference_percent = relative_diff * 100.0,
            pattern_length = pattern_len,
            outcome = "borderline",
            "ROBOT response divergence is borderline"
        );
    }

    tracing::debug!(
        event_name = "vulnerability.robot.response_divergence",
        response_pattern_count = response_patterns.len(),
        byte_differences,
        relative_difference_percent = relative_diff * 100.0,
        minimum_byte_differences = MIN_BYTE_DIFFERENCES,
        minimum_relative_difference_percent = MIN_RELATIVE_DIFFERENCE * 100.0,
        outcome = "noise",
        "ROBOT response divergence is below the oracle threshold"
    );
    RobotStatus::NotVulnerable
}

fn most_divergent_pair<'a>(patterns: &'a [&'a Vec<u8>]) -> Option<(&'a [u8], &'a [u8])> {
    let (&first, rest) = patterns.split_first()?;
    let &second = rest.first()?;
    let mut best = (first.as_slice(), second.as_slice());
    let mut best_diff = 0usize;

    for (i, left) in patterns.iter().enumerate() {
        for right in patterns.iter().skip(i + 1) {
            let diff = content_difference_count(left, right) + left.len().abs_diff(right.len());
            if diff > best_diff {
                best_diff = diff;
                best = (left.as_slice(), right.as_slice());
            }
        }
    }

    Some(best)
}

fn content_difference_count(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right.iter())
        .filter(|(left, right)| left != right)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(description: u8) -> Vec<u8> {
        vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description]
    }

    #[test]
    fn identical_patterns_are_not_vulnerable() {
        let response = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        let responses = vec![&response, &response];

        assert_eq!(
            classify_responses(&responses, &[vec![response.clone(), response.clone()]], 2),
            RobotStatus::NotVulnerable
        );
    }

    #[test]
    fn length_only_difference_is_not_an_oracle() {
        let one = vec![1, 2, 3];
        let two = vec![1, 2, 3, 4];
        let mut patterns = std::collections::BTreeSet::new();
        patterns.insert(one);
        patterns.insert(two);

        assert_eq!(
            classify_pattern_divergence(&patterns),
            RobotStatus::NotVulnerable
        );
    }

    #[test]
    fn large_content_difference_is_weak_oracle() {
        let one = vec![1, 2, 3, 4, 5, 6];
        let two = vec![9, 8, 7, 6, 5, 4];
        let mut patterns = std::collections::BTreeSet::new();
        patterns.insert(one);
        patterns.insert(two);

        assert_eq!(
            classify_pattern_divergence(&patterns),
            RobotStatus::WeakOracle
        );
    }

    #[test]
    fn distinct_confirmed_alerts_are_vulnerable() {
        let alert_46 = alert(0x46);
        let alert_47 = alert(0x47);

        assert_eq!(
            classify_responses(
                &[],
                &[
                    vec![alert_46.clone(), alert_46],
                    vec![alert_47.clone(), alert_47],
                ],
                2,
            ),
            RobotStatus::Vulnerable
        );
    }

    #[test]
    fn unconfirmed_or_inconsistent_alerts_are_inconclusive() {
        let alert_46 = alert(0x46);
        let alert_47 = alert(0x47);

        assert_eq!(
            classify_responses(&[], &[vec![alert_46.clone()]], 2),
            RobotStatus::Inconclusive
        );
        assert_eq!(
            classify_responses(&[], &[vec![alert_46, alert_47]], 2),
            RobotStatus::Inconclusive
        );
    }

    #[test]
    fn fewer_than_two_response_patterns_are_not_vulnerable() {
        let one = vec![1, 2, 3];
        assert_eq!(classify_responses(&[], &[], 1), RobotStatus::NotVulnerable);
        assert_eq!(
            classify_responses(&[&one, &one], &[], 1),
            RobotStatus::NotVulnerable
        );
    }

    #[test]
    fn equal_prefixes_and_small_divergence_are_not_vulnerable() {
        let one = vec![1; PATTERN_PREFIX_LEN + 5];
        let mut same_prefix = one.clone();
        same_prefix[PATTERN_PREFIX_LEN] = 2;
        assert_eq!(
            classify_responses(&[&one, &same_prefix], &[], 1),
            RobotStatus::NotVulnerable
        );

        let mut two_differences = vec![1; PATTERN_PREFIX_LEN];
        two_differences[0] = 2;
        two_differences[1] = 2;
        let mut patterns = std::collections::BTreeSet::new();
        patterns.insert(vec![1; PATTERN_PREFIX_LEN]);
        patterns.insert(two_differences);
        assert_eq!(
            classify_pattern_divergence(&patterns),
            RobotStatus::NotVulnerable
        );
    }

    #[test]
    fn no_distinct_patterns_are_inconclusive_for_divergence_analysis() {
        let patterns = std::collections::BTreeSet::new();
        assert_eq!(
            classify_pattern_divergence(&patterns),
            RobotStatus::Inconclusive
        );
    }
}
