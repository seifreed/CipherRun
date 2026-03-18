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
