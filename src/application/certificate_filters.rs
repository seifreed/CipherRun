#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateFilters {
    pub expired: bool,
    pub self_signed: bool,
    pub mismatched: bool,
    pub revoked: bool,
    pub untrusted: bool,
}

impl CertificateFilters {
    pub fn has_filters(&self) -> bool {
        self.expired || self.self_signed || self.mismatched || self.revoked || self.untrusted
    }

    pub fn active_filter_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.expired {
            names.push("expired");
        }
        if self.self_signed {
            names.push("self-signed");
        }
        if self.mismatched {
            names.push("mismatched");
        }
        if self.revoked {
            names.push("revoked");
        }
        if self.untrusted {
            names.push("untrusted");
        }
        names
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateFilters;

    #[test]
    fn reports_each_active_filter_in_stable_order() {
        let filters = CertificateFilters {
            expired: true,
            self_signed: true,
            mismatched: true,
            revoked: true,
            untrusted: true,
        };

        assert!(filters.has_filters());
        assert_eq!(
            filters.active_filter_names(),
            [
                "expired",
                "self-signed",
                "mismatched",
                "revoked",
                "untrusted"
            ]
        );
        assert!(!CertificateFilters::default().has_filters());
        assert!(
            CertificateFilters::default()
                .active_filter_names()
                .is_empty()
        );
    }
}
