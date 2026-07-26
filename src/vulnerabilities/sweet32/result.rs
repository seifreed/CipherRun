/// Sweet32 test result.
#[derive(Debug, Clone)]
pub struct Sweet32TestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub des3_ciphers: Vec<String>,
    pub details: String,
}

impl Sweet32TestResult {
    pub(super) fn from_des3_probe(des3_ciphers: Vec<String>, des3_inconclusive: bool) -> Self {
        let vulnerable = !des3_ciphers.is_empty();
        let inconclusive = !vulnerable && des3_inconclusive;
        let details = details_for_des3_probe(&des3_ciphers, vulnerable, inconclusive);

        Self {
            vulnerable,
            inconclusive,
            des3_ciphers,
            details,
        }
    }
}

fn details_for_des3_probe(des3_ciphers: &[String], vulnerable: bool, inconclusive: bool) -> String {
    if vulnerable {
        format!(
            "Vulnerable to Sweet32 (CVE-2016-2183): {} 3DES cipher(s) supported: {}",
            des3_ciphers.len(),
            des3_ciphers.join(", ")
        )
    } else if inconclusive {
        "SWEET32 test inconclusive - unable to determine 3DES cipher support".to_string()
    } else {
        "Not vulnerable - No 3DES (64-bit block) ciphers supported".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des3_cipher_marks_result_vulnerable() {
        let result = Sweet32TestResult::from_des3_probe(
            vec!["TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string()],
            false,
        );

        assert!(result.vulnerable);
        assert!(!result.inconclusive);
        assert!(result.details.contains("1 3DES cipher"));
    }

    #[test]
    fn inconclusive_clean_probe_marks_result_inconclusive() {
        let result = Sweet32TestResult::from_des3_probe(Vec::new(), true);

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
    }
}
