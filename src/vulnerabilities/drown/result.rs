use super::Sslv2Status;

/// DROWN test result.
#[derive(Debug, Clone)]
pub struct DrownTestResult {
    pub vulnerable: bool,
    pub sslv2_supported: bool,
    pub sslv2_export_ciphers: bool,
    /// Detailed SSLv2 export detection status (None if the probe did not run or was inconclusive)
    pub sslv2_export_status: Option<Sslv2Status>,
    /// Detailed SSLv2 detection status (None if test was inconclusive)
    pub sslv2_status: Option<Sslv2Status>,
    pub details: String,
}

impl DrownTestResult {
    pub(super) fn from_statuses(
        sslv2_status: Sslv2Status,
        sslv2_export_status: Option<Sslv2Status>,
    ) -> Self {
        let sslv2_supported = sslv2_status.is_vulnerable();
        let sslv2_export_ciphers = sslv2_export_status
            .as_ref()
            .is_some_and(Sslv2Status::is_vulnerable);

        Self {
            vulnerable: sslv2_supported,
            sslv2_supported,
            sslv2_export_ciphers,
            sslv2_export_status,
            sslv2_status: sslv2_status.detailed(),
            details: details(sslv2_status, sslv2_export_ciphers),
        }
    }
}

impl Sslv2Status {
    pub(super) fn detailed(self) -> Option<Self> {
        match self {
            Self::Inconclusive => None,
            _ => Some(self),
        }
    }

    pub(super) fn merge(self, next: Self) -> Self {
        if next.rank() > self.rank() {
            next
        } else {
            self
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Confirmed => 5,
            Self::Probable => 4,
            Self::Suspicious => 3,
            Self::Inconclusive => 2,
            Self::NotSupported => 1,
        }
    }
}

fn details(sslv2_status: Sslv2Status, sslv2_export: bool) -> String {
    match sslv2_status {
        Sslv2Status::Confirmed if sslv2_export => {
            "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 ServerHello received, export ciphers enabled (highly vulnerable)".to_string()
        }
        Sslv2Status::Confirmed => {
            "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 ServerHello received".to_string()
        }
        Sslv2Status::Probable if sslv2_export => {
            "Potentially vulnerable to DROWN - SSLv2 probable (known message type detected), export ciphers enabled".to_string()
        }
        Sslv2Status::Probable => {
            "Potentially vulnerable to DROWN - SSLv2 probable (known message type detected)".to_string()
        }
        Sslv2Status::Suspicious => {
            "DROWN: SSLv2-like response detected - manual verification recommended".to_string()
        }
        Sslv2Status::NotSupported => "Not vulnerable - SSLv2 not supported".to_string(),
        Sslv2Status::Inconclusive => {
            "DROWN test inconclusive - connection error prevented SSLv2 detection".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_highest_confidence_status() {
        assert_eq!(
            Sslv2Status::Suspicious.merge(Sslv2Status::Probable),
            Sslv2Status::Probable
        );
        assert_eq!(
            Sslv2Status::Confirmed.merge(Sslv2Status::NotSupported),
            Sslv2Status::Confirmed
        );
    }

    #[test]
    fn result_marks_confirmed_only_as_vulnerable() {
        let result = DrownTestResult::from_statuses(Sslv2Status::Probable, None);

        assert!(!result.vulnerable);
        assert!(!result.sslv2_supported);
        assert_eq!(result.sslv2_status, Some(Sslv2Status::Probable));
        assert!(result.details.contains("Potentially vulnerable"));
    }

    #[test]
    fn every_status_and_export_outcome_has_the_expected_result() {
        let cases = [
            (Sslv2Status::Confirmed, true, true, "highly vulnerable"),
            (Sslv2Status::Confirmed, false, true, "ServerHello received"),
            (Sslv2Status::Probable, true, false, "export ciphers enabled"),
            (
                Sslv2Status::Probable,
                false,
                false,
                "Potentially vulnerable",
            ),
            (Sslv2Status::Suspicious, false, false, "manual verification"),
            (Sslv2Status::NotSupported, false, false, "not supported"),
            (Sslv2Status::Inconclusive, false, false, "inconclusive"),
        ];

        for (status, export, vulnerable, detail) in cases {
            let export_status = export.then_some(Sslv2Status::Confirmed);
            let result = DrownTestResult::from_statuses(status, export_status);
            assert_eq!(result.vulnerable, vulnerable, "{status:?}");
            assert_eq!(result.sslv2_supported, status.is_vulnerable());
            assert_eq!(result.sslv2_status, status.detailed());
            assert_eq!(result.sslv2_export_ciphers, export);
            assert!(result.details.contains(detail), "{}", result.details);
        }
    }
}
