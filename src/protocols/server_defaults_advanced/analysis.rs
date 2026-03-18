use super::{DhStrength, KeyExchangeParams};

pub(super) fn estimate_dh_size(cipher_name: &str) -> u16 {
    if cipher_name.contains("DHE-RSA-AES256") || cipher_name.contains("DHE-RSA-AES128") {
        2048
    } else {
        1024
    }
}

pub(super) fn classify_dh_strength(size_bits: u16) -> DhStrength {
    match size_bits {
        0..=1023 => DhStrength::Weak,
        1024 => DhStrength::Moderate,
        2048 => DhStrength::Strong,
        _ => DhStrength::VeryStrong,
    }
}

pub(super) fn analyze_cipher_kex(cipher_name: &str) -> (String, bool, KeyExchangeParams) {
    if cipher_name.contains("ECDHE") {
        let curve = if cipher_name.contains("256") {
            "secp256r1".to_string()
        } else if cipher_name.contains("384") {
            "secp384r1".to_string()
        } else {
            "secp256r1".to_string()
        };

        (
            "ECDHE".to_string(),
            true,
            KeyExchangeParams::Ecdhe {
                curve,
                point_size: 256,
            },
        )
    } else if cipher_name.contains("DHE") || cipher_name.contains("EDH") {
        (
            "DHE".to_string(),
            true,
            KeyExchangeParams::Dhe {
                prime_size: 2048,
                generator: 2,
            },
        )
    } else if cipher_name.contains("RSA")
        || cipher_name.starts_with("AES")
        || cipher_name.starts_with("DES")
        || cipher_name.starts_with("3DES")
        || cipher_name.starts_with("RC4")
        || cipher_name.starts_with("CAMELLIA")
    {
        (
            "RSA".to_string(),
            false,
            KeyExchangeParams::Rsa { modulus_size: 2048 },
        )
    } else {
        ("Unknown".to_string(), false, KeyExchangeParams::Unknown)
    }
}

pub(super) fn estimate_key_size(params: &KeyExchangeParams) -> Option<u16> {
    match params {
        KeyExchangeParams::Rsa { modulus_size } => Some(*modulus_size),
        KeyExchangeParams::Dhe { prime_size, .. } => Some(*prime_size),
        KeyExchangeParams::Ecdhe { point_size, .. } => Some(*point_size),
        KeyExchangeParams::Unknown => None,
    }
}
