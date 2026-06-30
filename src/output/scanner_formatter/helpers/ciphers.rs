use crate::ciphers::tester::CipherCounts;
use colored::Colorize;

pub(crate) fn display_cipher_strength_distribution(counts: &CipherCounts) {
    println!("  Strength Distribution:");

    if counts.null_ciphers > 0 {
        println!(
            "    NULL:    {} {}",
            counts.null_ciphers,
            "!! CRITICAL".red().bold()
        );
    }
    if counts.export_ciphers > 0 {
        println!("    EXPORT:  {} {}", counts.export_ciphers, "!! WEAK".red());
    }
    if counts.low_strength > 0 {
        println!("    LOW:     {} {}", counts.low_strength, "!".yellow());
    }
    if counts.medium_strength > 0 {
        println!("    MEDIUM:  {}", counts.medium_strength);
    }
    if counts.high_strength > 0 {
        println!("    HIGH:    {} {}", counts.high_strength, "Y".green());
    }
}

pub(crate) fn display_cipher_security_features(counts: &CipherCounts) {
    println!("\n  Security Features:");
    println!(
        "    Forward Secrecy: {}/{} ({}%)",
        counts.forward_secrecy,
        counts.total,
        cipher_feature_percentage(counts.forward_secrecy, counts.total)
    );
    println!(
        "    AEAD:            {}/{} ({}%)",
        counts.aead,
        counts.total,
        cipher_feature_percentage(counts.aead, counts.total)
    );
}

fn cipher_feature_percentage(feature_count: usize, total: usize) -> usize {
    if total == 0 {
        return 0;
    }

    let percentage = (feature_count as u128)
        .saturating_mul(100)
        .checked_div(total as u128)
        .unwrap_or(0);
    usize::try_from(percentage.min(100)).expect("percentage is capped at 100")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_feature_percentage_handles_extreme_counts() {
        assert_eq!(cipher_feature_percentage(2, 5), 40);
        assert_eq!(cipher_feature_percentage(usize::MAX, usize::MAX), 100);
        assert_eq!(cipher_feature_percentage(1, 0), 0);
    }
}
