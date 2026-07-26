use super::parse::read_u16_at;
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CodeSignal {
    ConfirmedOracle,
    Inconclusive,
    None,
}

/// Extract the description byte from a TLS alert record only if the record is
/// structurally complete.
pub(super) fn alert_description_code(response: &[u8]) -> Option<u8> {
    if response.len() >= 7 && response.first() == Some(&0x15) {
        let record_len = usize::from(read_u16_at(response, 3)?);
        if record_len == 2 && response.len() == 5 + record_len {
            return response.get(6).copied();
        }
    }
    None
}

pub(super) fn classify(per_vector: &[Vec<Vec<u8>>], confirmation_rounds: usize) -> CodeSignal {
    let mut stable_codes: HashSet<u8> = HashSet::new();
    let mut missing_confirmation = false;
    for probes in per_vector {
        let codes: HashSet<u8> = probes
            .iter()
            .filter_map(|response| alert_description_code(response))
            .collect();
        if codes.is_empty() {
            continue;
        }
        if probes.len() < confirmation_rounds {
            missing_confirmation = true;
            continue;
        }
        match codes.len() {
            1 => stable_codes.extend(codes),
            _ => return CodeSignal::Inconclusive,
        }
    }

    if stable_codes.len() > 1 {
        CodeSignal::ConfirmedOracle
    } else if missing_confirmation {
        CodeSignal::Inconclusive
    } else {
        CodeSignal::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_alert_record_with_trailing_bytes() {
        let response = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00];
        assert_eq!(alert_description_code(&response), None);
    }

    #[test]
    fn requires_confirmed_samples() {
        let alert_46 = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        let alert_47 = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x47];
        let per_vector = vec![vec![alert_46], vec![alert_47]];

        assert_eq!(classify(&per_vector, 2), CodeSignal::Inconclusive);
    }
}
