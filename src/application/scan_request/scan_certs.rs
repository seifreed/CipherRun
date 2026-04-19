#[derive(Debug, Clone, Default)]
pub struct ScanRequestCerts {
    pub analyze_certificates: bool,
    pub ocsp: bool,
    pub no_check_certificate: bool,
}
