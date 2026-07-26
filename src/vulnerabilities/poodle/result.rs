/// POODLE test result.
#[derive(Debug, Clone)]
pub struct PoodleTestResult {
    pub vulnerable: bool,
    pub ssl3_supported: Option<bool>,
    pub tls_poodle: Option<bool>,
    pub details: String,
    pub variants: Vec<PoodleVariantResult>,
}

impl PoodleTestResult {
    pub(super) fn from_basic_probes(
        ssl3_supported: Option<bool>,
        tls_poodle: Option<bool>,
    ) -> Self {
        Self {
            vulnerable: ssl3_supported == Some(true) || tls_poodle == Some(true),
            ssl3_supported,
            tls_poodle,
            details: basic_details(ssl3_supported, tls_poodle),
            variants: Vec::new(),
        }
    }

    pub(super) fn from_variant_results(
        ssl3_supported: Option<bool>,
        tls_poodle: Option<bool>,
        variants: Vec<PoodleVariantResult>,
    ) -> Self {
        let vulnerable = variants.iter().any(|variant| variant.vulnerable);
        let inconclusive = variants.iter().any(|variant| variant.inconclusive);

        Self {
            vulnerable,
            ssl3_supported,
            tls_poodle,
            details: variant_details(&variants, vulnerable, inconclusive),
            variants,
        }
    }
}

fn basic_details(ssl3_supported: Option<bool>, tls_poodle: Option<bool>) -> String {
    match (ssl3_supported, tls_poodle) {
        (Some(true), Some(true)) => "Vulnerable: SSL 3.0 supported (CVE-2014-3566) AND TLS POODLE detected (CVE-2014-8730)".to_string(),
        (Some(true), _) => "Vulnerable: SSL 3.0 is supported (CVE-2014-3566)".to_string(),
        (Some(false), Some(true)) => "Vulnerable: TLS implementation vulnerable to POODLE (CVE-2014-8730)".to_string(),
        (Some(false), None) => "SSL 3.0 disabled. TLS POODLE test inconclusive - no CBC cipher connection could be established to probe for a padding oracle".to_string(),
        (Some(false), Some(false)) => "Not vulnerable: SSL 3.0 disabled and CBC-based TLS POODLE was not observed".to_string(),
        (None, _) => "SSL 3.0 support inconclusive - unable to complete the SSL 3.0 probe".to_string(),
    }
}

fn variant_details(
    variants: &[PoodleVariantResult],
    vulnerable: bool,
    inconclusive: bool,
) -> String {
    if vulnerable {
        let names: Vec<_> = variants
            .iter()
            .filter(|variant| variant.vulnerable)
            .map(|variant| variant.variant.name())
            .collect();
        format!("Vulnerable to: {}", names.join(", "))
    } else if inconclusive {
        "POODLE variant testing inconclusive".to_string()
    } else {
        "Not vulnerable to any POODLE variants".to_string()
    }
}

/// POODLE vulnerability variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoodleVariant {
    /// Classic POODLE - CVE-2014-3566 - SSLv3 CBC padding oracle
    SslV3,
    /// TLS POODLE - CVE-2014-8730 - TLS CBC padding oracle
    Tls,
    /// Zombie POODLE - CVE-2019-5592 - Observable MAC validity despite invalid padding
    ZombiePoodle,
    /// GOLDENDOODLE - CVE-2019-5592 - Padding oracle with error response differentiation
    GoldenDoodle,
    /// Sleeping POODLE - CVE-2019-5592 - Timing-based padding oracle
    SleepingPoodle,
    /// OpenSSL 0-Length Fragment - CVE-2011-4576 - Zero-length TLS record vulnerability
    OpenSsl0Length,
}

impl PoodleVariant {
    /// Get human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::SslV3 => "POODLE (SSLv3)",
            Self::Tls => "POODLE (TLS)",
            Self::ZombiePoodle => "Zombie POODLE",
            Self::GoldenDoodle => "GOLDENDOODLE",
            Self::SleepingPoodle => "Sleeping POODLE",
            Self::OpenSsl0Length => "OpenSSL 0-Length Fragment",
        }
    }

    /// Get CVE identifier.
    pub fn cve(&self) -> &'static str {
        match self {
            Self::SslV3 => "CVE-2014-3566",
            Self::Tls => "CVE-2014-8730",
            Self::ZombiePoodle | Self::GoldenDoodle | Self::SleepingPoodle => "CVE-2019-5592",
            Self::OpenSsl0Length => "CVE-2011-4576",
        }
    }

    /// Get vulnerability description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::SslV3 => "SSL 3.0 CBC padding oracle - allows plaintext recovery",
            Self::Tls => "TLS CBC padding oracle - similar to SSLv3 POODLE",
            Self::ZombiePoodle => "Observable MAC validity oracle despite invalid padding",
            Self::GoldenDoodle => "Padding oracle through error response differentiation",
            Self::SleepingPoodle => "Timing-based padding oracle vulnerability",
            Self::OpenSsl0Length => "Zero-length TLS fragment padding vulnerability",
        }
    }
}

/// Result for a specific POODLE variant test.
#[derive(Debug, Clone)]
pub struct PoodleVariantResult {
    pub variant: PoodleVariant,
    pub vulnerable: bool,
    /// True when the probe could not reach a conclusive verdict (e.g., insufficient
    /// timing samples, CBC unsupported for the variant, or the server reset the
    /// connection before the oracle could be observed). V3 fix: replaces an
    /// earlier string-based check (`details.contains("Inconclusive")`) that
    /// missed the "Insufficient timing samples" message variant.
    pub inconclusive: bool,
    pub details: String,
    pub timing_data: Option<TimingData>,
}

/// Timing analysis data for timing-based variants.
#[derive(Debug, Clone)]
pub struct TimingData {
    pub valid_padding_avg_ms: f64,
    pub invalid_padding_avg_ms: f64,
    pub timing_difference_ms: f64,
    pub samples_collected: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_result_marks_tls_poodle_vulnerable() {
        let result = PoodleTestResult::from_basic_probes(Some(false), Some(true));

        assert!(result.vulnerable);
        assert!(result.details.contains("TLS implementation vulnerable"));
    }

    #[test]
    fn variant_result_summarizes_vulnerable_names() {
        let result = PoodleTestResult::from_variant_results(
            Some(false),
            Some(true),
            vec![PoodleVariantResult {
                variant: PoodleVariant::ZombiePoodle,
                vulnerable: true,
                inconclusive: false,
                details: "vulnerable".to_string(),
                timing_data: None,
            }],
        );

        assert!(result.vulnerable);
        assert_eq!(result.details, "Vulnerable to: Zombie POODLE");
    }
}
