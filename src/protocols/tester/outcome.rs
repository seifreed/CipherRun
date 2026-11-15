#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::protocols::tester) enum ProtocolProbeOutcome {
    Supported,
    NotSupported,
    Inconclusive,
}

impl ProtocolProbeOutcome {
    pub(in crate::protocols::tester) fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }

    pub(in crate::protocols::tester) fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }
}
