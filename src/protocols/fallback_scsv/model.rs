#[derive(Debug, Clone, Copy)]
pub(super) struct ScsvSupport {
    pub(super) supported: bool,
    pub(super) vulnerable: bool,
    pub(super) accepts_downgrade: bool,
    pub(super) inconclusive: bool,
    pub(super) not_applicable: bool,
}

impl ScsvSupport {
    pub(super) fn supported() -> Self {
        Self {
            supported: true,
            vulnerable: false,
            accepts_downgrade: false,
            inconclusive: false,
            not_applicable: false,
        }
    }

    pub(super) fn not_supported() -> Self {
        Self {
            supported: false,
            vulnerable: true,
            accepts_downgrade: true,
            inconclusive: false,
            not_applicable: false,
        }
    }

    pub(super) fn inconclusive() -> Self {
        Self {
            supported: false,
            vulnerable: false,
            accepts_downgrade: false,
            inconclusive: true,
            not_applicable: false,
        }
    }

    pub(super) fn not_applicable() -> Self {
        Self {
            supported: false,
            vulnerable: false,
            accepts_downgrade: false,
            inconclusive: false,
            not_applicable: true,
        }
    }
}

/// TLS_FALLBACK_SCSV test result
#[derive(Debug, Clone)]
pub struct FallbackScsvTestResult {
    pub supported: bool,
    pub accepts_downgrade: bool,
    pub vulnerable: bool,
    pub not_applicable: bool,
    pub details: String,
    pub has_tls13_or_higher: bool,
}
