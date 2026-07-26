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
            "ROBOT: {} patterns differ only in length ({} bytes) — TCP noise, not an oracle",
            response_patterns.len(),
            len_difference
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
            "ROBOT: Weak oracle detected - {} byte differences ({:.1}% of {} bytes)",
            byte_differences,
            relative_diff * 100.0,
            pattern_len
        );
        return RobotStatus::WeakOracle;
    }

    if byte_differences >= 2 {
        tracing::info!(
            "ROBOT: Borderline detection - {} byte differences ({:.1}% of pattern), manual investigation recommended",
            byte_differences,
            relative_diff * 100.0
        );
    }

    tracing::debug!(
        "ROBOT: {} patterns detected but only {} byte differences (min: {} or {:.0}%), likely noise",
        response_patterns.len(),
        byte_differences,
        MIN_BYTE_DIFFERENCES,
        MIN_RELATIVE_DIFFERENCE * 100.0
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
}
