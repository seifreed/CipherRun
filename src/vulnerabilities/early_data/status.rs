#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::vulnerabilities::early_data) enum EarlyDataSupportStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::vulnerabilities::early_data) enum Tls13SupportStatus {
    Supported,
    NotSupported,
    Inconclusive,
}
