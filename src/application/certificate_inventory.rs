use chrono::Utc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateInventorySort {
    ExpiryAsc,
    ExpiryDesc,
    IssuedAsc,
    IssuedDesc,
}

#[derive(Debug, Clone)]
pub struct CertificateInventoryQuery {
    pub limit: usize,
    pub offset: usize,
    pub sort: CertificateInventorySort,
    pub hostname: Option<String>,
    pub expiring_within_days: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CertificateInventoryRecord {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: chrono::DateTime<Utc>,
    pub not_after: chrono::DateTime<Utc>,
    pub san_json: Option<String>,
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateInventoryPage {
    pub total: usize,
    pub certificates: Vec<CertificateInventoryRecord>,
}
