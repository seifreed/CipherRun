use colored::*;

use crate::ciphers::tester::CipherCounts;

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
    let total = counts.total.max(1);
    println!("\n  Security Features:");
    println!(
        "    Forward Secrecy: {}/{} ({}%)",
        counts.forward_secrecy,
        counts.total,
        (counts.forward_secrecy * 100) / total
    );
    println!(
        "    AEAD:            {}/{} ({}%)",
        counts.aead,
        counts.total,
        (counts.aead * 100) / total
    );
}
