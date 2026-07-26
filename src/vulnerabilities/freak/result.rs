/// FREAK test result.
#[derive(Debug, Clone)]
pub struct FreakTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub export_ciphers: Vec<String>,
    pub details: String,
}

impl FreakTestResult {
    pub(super) fn from_export_probe(
        export_ciphers: Vec<String>,
        export_inconclusive: bool,
    ) -> Self {
        let vulnerable = !export_ciphers.is_empty();
        let inconclusive = !vulnerable && export_inconclusive;
        let details = details_for_export_probe(&export_ciphers, vulnerable, inconclusive);

        Self {
            vulnerable,
            inconclusive,
            export_ciphers,
            details,
        }
    }
}

fn details_for_export_probe(
    export_ciphers: &[String],
    vulnerable: bool,
    inconclusive: bool,
) -> String {
    if vulnerable {
        format!(
            "Vulnerable to FREAK (CVE-2015-0204) - Server supports {} RSA export cipher(s): {}",
            export_ciphers.len(),
            export_ciphers.join(", ")
        )
    } else if inconclusive {
        "FREAK test inconclusive - unable to determine RSA export cipher support".to_string()
    } else {
        "Not vulnerable - No RSA export ciphers supported".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_cipher_marks_result_vulnerable() {
        let result = FreakTestResult::from_export_probe(vec!["EXP-RC4-MD5".to_string()], false);

        assert!(result.vulnerable);
        assert!(!result.inconclusive);
        assert!(result.details.contains("1 RSA export cipher"));
    }

    #[test]
    fn inconclusive_clean_probe_marks_result_inconclusive() {
        let result = FreakTestResult::from_export_probe(Vec::new(), true);

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
    }
}
