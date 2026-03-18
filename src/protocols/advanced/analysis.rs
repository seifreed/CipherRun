use super::{CipherDetails, CipherStrength, FsGrade, Rc4BiasesAnalysis};

pub(super) fn analyze_cipher_details(cipher_name: &str) -> CipherDetails {
    let forward_secrecy = cipher_name.contains("ECDHE") || cipher_name.contains("DHE");

    let key_exchange = if cipher_name.starts_with("TLS_") || cipher_name.contains("ECDHE") {
        "ECDHE".to_string()
    } else if cipher_name.contains("DHE") {
        "DHE".to_string()
    } else if cipher_name.contains("RSA") {
        "RSA".to_string()
    } else {
        "Unknown".to_string()
    };

    let encryption = if cipher_name.contains("AES256-GCM") {
        "AES-256-GCM".to_string()
    } else if cipher_name.contains("AES128-GCM") {
        "AES-128-GCM".to_string()
    } else if cipher_name.contains("AES256") {
        "AES-256-CBC".to_string()
    } else if cipher_name.contains("AES128") {
        "AES-128-CBC".to_string()
    } else if cipher_name.contains("CHACHA20") {
        "ChaCha20-Poly1305".to_string()
    } else if cipher_name.contains("3DES") {
        "3DES".to_string()
    } else if cipher_name.contains("RC4") {
        "RC4".to_string()
    } else {
        "Unknown".to_string()
    };

    let mac = if cipher_name.contains("GCM") || cipher_name.contains("POLY1305") {
        "AEAD".to_string()
    } else if cipher_name.contains("SHA384") {
        "SHA384".to_string()
    } else if cipher_name.contains("SHA256") {
        "SHA256".to_string()
    } else if cipher_name.contains("SHA") {
        "SHA1".to_string()
    } else if cipher_name.contains("MD5") {
        "MD5".to_string()
    } else {
        "Unknown".to_string()
    };

    let strength = classify_cipher_strength(cipher_name, forward_secrecy, &encryption, &mac);

    CipherDetails {
        name: cipher_name.to_string(),
        strength,
        key_exchange,
        encryption,
        mac,
        forward_secrecy,
    }
}

pub(super) fn classify_cipher_strength(
    cipher: &str,
    fs: bool,
    enc: &str,
    mac: &str,
) -> CipherStrength {
    if cipher.contains("EXP")
        || cipher.contains("NULL")
        || cipher.contains("DES-CBC-")
        || mac == "MD5"
    {
        return CipherStrength::Weak;
    }

    if cipher.contains("3DES") || cipher.contains("RC4") || (!fs && !cipher.starts_with("TLS_")) {
        return CipherStrength::Medium;
    }

    if (enc.contains("GCM") || enc.contains("Poly1305")) && fs {
        return CipherStrength::VeryStrong;
    }

    if enc.contains("AES") && fs {
        return CipherStrength::Strong;
    }

    CipherStrength::Medium
}

pub(super) fn classify_fs_grade(percentage: f64, supported: bool) -> FsGrade {
    if !supported {
        FsGrade::F
    } else if percentage >= 100.0 {
        FsGrade::A
    } else if percentage >= 80.0 {
        FsGrade::B
    } else if percentage >= 50.0 {
        FsGrade::C
    } else {
        FsGrade::D
    }
}

pub(super) fn grade_to_string(grade: FsGrade) -> &'static str {
    match grade {
        FsGrade::A => "A",
        FsGrade::B => "B",
        FsGrade::C => "C",
        FsGrade::D => "D",
        FsGrade::F => "F",
    }
}

pub(super) fn build_rc4_report(supported_rc4_ciphers: Vec<String>) -> Rc4BiasesAnalysis {
    let rc4_supported = !supported_rc4_ciphers.is_empty();
    let vulnerable_to_appelbaum = rc4_supported;
    let vulnerable_to_bar_mitzvah = rc4_supported;

    let bias_details = if rc4_supported {
        format!(
            "RC4 is vulnerable to multiple bias attacks:\n\
                - Appelbaum attack (2013): Statistical biases in RC4 keystream\n\
                - Bar Mitzvah attack (2015): Exploits biases in first 256 bytes\n\
                - NOMORE attack (2015): Single-byte biases in TLS\n\
                Supported RC4 ciphers: {}",
            supported_rc4_ciphers.join(", ")
        )
    } else {
        "RC4 not supported - not vulnerable to bias attacks".to_string()
    };

    Rc4BiasesAnalysis {
        rc4_supported,
        rc4_ciphers: supported_rc4_ciphers,
        vulnerable_to_appelbaum,
        vulnerable_to_bar_mitzvah,
        bias_details,
    }
}
