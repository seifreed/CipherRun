use crate::Result;
use crate::application::{PersistedScan, ScanResults, ScanResultsStore, ScanResultsStoreFactory};
/// Application use case for persisting scan results.
pub struct StoreScanResults;

impl StoreScanResults {
    pub async fn execute_with_store(
        store: &dyn ScanResultsStore,
        results: &ScanResults,
    ) -> Result<i64> {
        let persisted = PersistedScan::from_scan_results(results);
        store.store_scan(&persisted).await
    }

    pub async fn execute_with_factory(
        factory: &dyn ScanResultsStoreFactory,
        config_path: &std::path::Path,
        results: &ScanResults,
    ) -> Result<i64> {
        let store = factory.open(config_path).await?;
        Self::execute_with_store(store.as_ref(), results).await
    }
}
