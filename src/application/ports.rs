use crate::application::{
    CertificateInventoryPage, CertificateInventoryQuery, CertificateInventoryRecord, PersistedScan,
    ScanHistoryEntry, ScanHistoryQuery,
};
use async_trait::async_trait;
use std::path::Path;

#[async_trait]
pub trait ScanResultsStore: Send + Sync {
    async fn store_scan(&self, scan: &PersistedScan) -> crate::Result<i64>;
}

#[async_trait]
pub trait ScanResultsStoreFactory: Send + Sync {
    async fn open(&self, config_path: &Path) -> crate::Result<Box<dyn ScanResultsStore>>;
}

pub trait PolicySource: Send + Sync {
    fn load_policy(&self, policy_path: &Path) -> crate::Result<crate::policy::Policy>;
}

pub trait ComplianceFrameworkSource: Send + Sync {
    fn load_framework(
        &self,
        framework_id: &str,
    ) -> crate::Result<crate::compliance::ComplianceFramework>;
}

#[async_trait]
pub trait CertificateInventoryPort: Send + Sync {
    async fn list_certificates(
        &self,
        query: &CertificateInventoryQuery,
    ) -> crate::Result<CertificateInventoryPage>;

    async fn get_certificate(
        &self,
        fingerprint: &str,
    ) -> crate::Result<Option<CertificateInventoryRecord>>;
}

#[async_trait]
pub trait ScanHistoryPort: Send + Sync {
    async fn get_history(&self, query: &ScanHistoryQuery) -> crate::Result<Vec<ScanHistoryEntry>>;
}
