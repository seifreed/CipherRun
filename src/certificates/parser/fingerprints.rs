use crate::Result;
use base64::Engine;
use chrono::{DateTime, Utc};
use openssl::hash::MessageDigest;
use openssl::x509::X509 as OpensslX509;

/// Calculate Pin SHA256 for HPKP (HTTP Public Key Pinning) per RFC 7469
///
/// This function calculates the Base64-encoded SHA256 hash of the certificate's
/// SubjectPublicKeyInfo (SPKI) in DER format. This is the standard format used
/// for Public Key Pinning as defined in RFC 7469.
///
/// Algorithm:
/// 1. Extract the SubjectPublicKeyInfo from the certificate
/// 2. Compute SHA256 hash of the SPKI in DER format
/// 3. Base64-encode the hash
///
/// The pin can be used for HPKP headers and certificate validation.
///
/// # Arguments
/// * `der_bytes` - The certificate in DER format
///
/// # Returns
/// * `Ok(Some(String))` - Base64-encoded SHA256 pin on success
/// * `Ok(None)` - If public key cannot be extracted
/// * `Err` - On certificate parsing errors
pub(crate) fn calculate_pin_sha256(der_bytes: &[u8]) -> Result<Option<String>> {
    // Parse certificate using OpenSSL (which provides public_key_to_der)
    let cert =
        OpensslX509::from_der(der_bytes).map_err(|e| crate::error::TlsError::ParseError {
            message: format!("Failed to parse certificate with OpenSSL: {}", e),
        })?;

    // Extract public key
    let public_key = cert.public_key().map_err(|e| {
        crate::error::TlsError::Other(format!("Failed to extract public key: {}", e))
    })?;

    // Get SubjectPublicKeyInfo in DER format
    // This is the SPKI (SubjectPublicKeyInfo) structure, which includes:
    // - Algorithm identifier
    // - Public key bit string
    let spki_der = public_key.public_key_to_der().map_err(|e| {
        crate::error::TlsError::Other(format!("Failed to encode public key to DER: {}", e))
    })?;

    // Calculate SHA256 hash of SPKI
    let digest = openssl::hash::hash(MessageDigest::sha256(), &spki_der).map_err(|e| {
        crate::error::TlsError::Other(format!("Failed to compute SHA256 hash: {}", e))
    })?;

    // Base64 encode the hash
    let pin = base64::engine::general_purpose::STANDARD.encode(digest);

    Ok(Some(pin))
}

/// Calculate certificate fingerprint SHA256
///
/// This function calculates the SHA256 hash of the entire DER-encoded certificate,
/// formatted as a colon-separated hex string (e.g., "44:69:4E:E4:...").
/// This is the same format shown by SSL Labs and other certificate analysis tools.
///
/// Algorithm:
/// 1. Compute SHA256 hash of the entire DER-encoded certificate
/// 2. Format as uppercase hex string with colon separators
///
/// # Arguments
/// * `der_bytes` - The certificate in DER format
///
/// # Returns
/// * `Ok(Some(String))` - Colon-separated hex SHA256 fingerprint on success
/// * `Err` - On hash calculation errors
pub(crate) fn calculate_fingerprint_sha256(der_bytes: &[u8]) -> Result<Option<String>> {
    // Calculate SHA256 hash of entire certificate
    let digest = openssl::hash::hash(MessageDigest::sha256(), der_bytes).map_err(|e| {
        crate::error::TlsError::Other(format!("Failed to compute SHA256 hash: {}", e))
    })?;

    // Format as colon-separated hex string (uppercase)
    let fingerprint = digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    Ok(Some(fingerprint))
}

/// Calculate years, months, and remaining days from a total number of days.
pub(crate) fn calculate_duration_parts(days: i64) -> (i64, i64, i64) {
    let years = days / 365;
    let remaining_days = days % 365;
    let months = remaining_days / 30;
    let final_days = remaining_days % 30;
    (years, months, final_days)
}

/// Format a time phrase for certificate expiry display.
pub(crate) fn format_time_phrase(years: i64, months: i64, days: i64, is_expired: bool) -> String {
    let (prefix, suffix) = if is_expired {
        ("expired ", " ago")
    } else {
        ("expires in ", "")
    };

    fn pluralize(n: i64, singular: &str) -> String {
        if n == 1 {
            format!("1 {}", singular)
        } else {
            format!("{} {}s", n, singular)
        }
    }

    let phrase = if years > 0 {
        if months > 0 {
            format!(
                "{} and {}",
                pluralize(years, "year"),
                pluralize(months, "month")
            )
        } else {
            pluralize(years, "year")
        }
    } else if months > 0 {
        if days > 0 {
            format!(
                "{} and {}",
                pluralize(months, "month"),
                pluralize(days, "day")
            )
        } else {
            pluralize(months, "month")
        }
    } else {
        pluralize(days, "day")
    };

    format!("{}{}{}", prefix, phrase, suffix)
}

pub(crate) fn format_expiry_countdown(not_after_str: &str) -> Option<String> {
    use chrono::NaiveDateTime;

    let not_after = chrono::DateTime::parse_from_rfc3339(not_after_str)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDateTime::parse_from_str(not_after_str, "%Y-%m-%d %H:%M:%S UTC")
                .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
        })
        .or_else(|_| {
            let cleaned = not_after_str.replace(" UTC", "").replace(" GMT", "");
            NaiveDateTime::parse_from_str(&cleaned, "%Y-%m-%d %H:%M:%S")
                .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
        })
        .ok()?;

    let duration = not_after.signed_duration_since(Utc::now());
    let is_expired = duration.num_seconds() < 0;
    let total_days = duration.num_days().abs();

    if total_days == 0 {
        return Some(
            if is_expired {
                "expired today"
            } else {
                "expires today"
            }
            .to_string(),
        );
    }

    let (years, months, days) = calculate_duration_parts(total_days);
    Some(format_time_phrase(years, months, days, is_expired))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_pin_sha256_function() {
        // Test the calculate_pin_sha256 function with a self-generated certificate
        use openssl::asn1::Asn1Time;
        use openssl::bn::{BigNum, MsbOption};
        use openssl::hash::MessageDigest as OpensslMessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        // Generate RSA key pair
        let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");
        let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey from RSA");

        // Create certificate builder
        let mut builder = X509Builder::new().expect("Failed to create X509Builder");
        builder.set_version(2).expect("Failed to set version");

        let mut serial = BigNum::new().expect("Failed to create BigNum");
        serial
            .rand(128, MsbOption::MAYBE_ZERO, false)
            .expect("Failed to generate random serial");
        let serial = serial
            .to_asn1_integer()
            .expect("Failed to convert to ASN1 integer");
        builder
            .set_serial_number(&serial)
            .expect("Failed to set serial number");

        // Set subject name
        let mut name_builder = X509NameBuilder::new().expect("Failed to create X509NameBuilder");
        name_builder
            .append_entry_by_text("C", "US")
            .expect("Failed to set country");
        name_builder
            .append_entry_by_text("O", "Test")
            .expect("Failed to set organization");
        name_builder
            .append_entry_by_text("CN", "test.example.com")
            .expect("Failed to set common name");
        let name = name_builder.build();
        builder
            .set_subject_name(&name)
            .expect("Failed to set subject name");
        builder
            .set_issuer_name(&name)
            .expect("Failed to set issuer name");

        // Set validity period
        let not_before = Asn1Time::days_from_now(0).expect("Failed to create not_before time");
        let not_after = Asn1Time::days_from_now(365).expect("Failed to create not_after time");
        builder
            .set_not_before(&not_before)
            .expect("Failed to set not_before");
        builder
            .set_not_after(&not_after)
            .expect("Failed to set not_after");

        // Set public key
        builder.set_pubkey(&pkey).expect("Failed to set public key");

        // Sign the certificate
        builder
            .sign(&pkey, OpensslMessageDigest::sha256())
            .expect("Failed to sign certificate");
        let cert = builder.build();

        // Get DER bytes
        let der_bytes = cert.to_der().expect("Failed to convert certificate to DER");

        // Calculate pin
        let pin = calculate_pin_sha256(&der_bytes).expect("Failed to calculate pin SHA256");

        assert!(
            pin.is_some(),
            "Pin should be calculated for self-signed cert"
        );
        assert_eq!(
            pin.as_ref().expect("Pin should be Some").len(),
            44,
            "Pin should be 44 characters"
        );

        println!(
            "Test certificate Pin SHA256: {}",
            pin.expect("Pin should be present")
        );
    }

    #[test]
    fn test_duration_format_helpers() {
        let (y, m, d) = calculate_duration_parts(800);
        assert_eq!((y, m, d), (2, 2, 10));

        let phrase = format_time_phrase(1, 0, 0, false);
        assert!(phrase.contains("expires in 1 year"));

        let phrase = format_time_phrase(0, 2, 5, true);
        assert!(phrase.contains("expired 2 months and 5 days ago"));

        let today = format_expiry_countdown(&Utc::now().to_rfc3339()).unwrap();
        assert!(today.contains("expires today") || today.contains("expired today"));
    }
}
