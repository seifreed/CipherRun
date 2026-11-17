#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::vulnerabilities::early_data) enum EarlyDataSupportStatus {
    #[cfg_attr(not(feature = "rustls"), allow(dead_code))]
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
