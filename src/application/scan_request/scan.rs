use super::{
    ScanRequestCerts, ScanRequestCiphers, ScanRequestPrefs, ScanRequestProto, ScanRequestScope,
    ScanRequestVulns,
};

#[derive(Debug, Clone, Default)]
pub struct ScanRequestScan {
    pub scope: ScanRequestScope,
    pub proto: ScanRequestProto,
    pub ciphers: ScanRequestCiphers,
    pub vulns: ScanRequestVulns,
    pub certs: ScanRequestCerts,
    pub prefs: ScanRequestPrefs,
}
