use crate::Result;
use crate::application::{PersistedScan, ScanResults, ScanResultsStore, ScanResultsStoreFactory};
/// Application use case for persisting scan results.
pub struct StoreScanResults;

impl StoreScanResults {
    pub async fn execute_with_store(
        store: &dyn ScanResultsStore,
        results: &ScanResults,
    ) -> Result<i64> {
        let persisted = PersistedScan::try_from_scan_results(results)?;
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

#[cfg(test)]
mod tests {
    use super::StoreScanResults;
    use crate::application::{
        PersistedScan, ScanResults, ScanResultsStore, ScanResultsStoreFactory,
    };
    use crate::{Result, TlsError};
    use async_trait::async_trait;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct TestStore {
        persisted: Arc<Mutex<Vec<PersistedScan>>>,
        fail: bool,
    }

    #[async_trait]
    impl ScanResultsStore for TestStore {
        async fn store_scan(&self, scan: &PersistedScan) -> Result<i64> {
            self.persisted.lock().unwrap().push(scan.clone());
            if self.fail {
                Err(TlsError::ConfigError {
                    message: "store failed".to_string(),
                })
            } else {
                Ok(42)
            }
        }
    }

    struct TestFactory {
        store: TestStore,
        opened_path: Arc<Mutex<Option<PathBuf>>>,
        fail: bool,
    }

    #[async_trait]
    impl ScanResultsStoreFactory for TestFactory {
        async fn open(&self, config_path: &Path) -> Result<Box<dyn ScanResultsStore>> {
            *self.opened_path.lock().unwrap() = Some(config_path.to_path_buf());
            if self.fail {
                Err(TlsError::ConfigError {
                    message: "factory failed".to_string(),
                })
            } else {
                Ok(Box::new(self.store.clone()))
            }
        }
    }

    fn store(fail: bool) -> TestStore {
        TestStore {
            persisted: Arc::default(),
            fail,
        }
    }

    fn results(target: &str) -> ScanResults {
        ScanResults {
            target: target.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn execute_with_store_persists_results_and_returns_id() {
        let store = store(false);
        let id = StoreScanResults::execute_with_store(&store, &results("api.example.com.:8443"))
            .await
            .unwrap();

        assert_eq!(id, 42);
        let persisted = store.persisted.lock().unwrap();
        assert_eq!(persisted[0].target_hostname, "api.example.com");
        assert_eq!(persisted[0].target_port, 8443);
    }

    #[tokio::test]
    async fn execute_with_store_propagates_store_failure() {
        let store = store(true);
        let error = StoreScanResults::execute_with_store(&store, &results("example.com"))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("store failed"));
        assert_eq!(store.persisted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn execute_with_factory_opens_config_and_persists_results() {
        let store = store(false);
        let opened_path: Arc<Mutex<Option<PathBuf>>> = Arc::default();
        let factory = TestFactory {
            store: store.clone(),
            opened_path: opened_path.clone(),
            fail: false,
        };
        let config_path = Path::new("database.toml");

        let id =
            StoreScanResults::execute_with_factory(&factory, config_path, &results("example.com"))
                .await
                .unwrap();

        assert_eq!(id, 42);
        assert_eq!(opened_path.lock().unwrap().as_deref(), Some(config_path));
        assert_eq!(store.persisted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn execute_with_factory_propagates_open_failure() {
        let factory = TestFactory {
            store: store(false),
            opened_path: Arc::default(),
            fail: true,
        };

        let error = StoreScanResults::execute_with_factory(
            &factory,
            Path::new("database.toml"),
            &results("example.com"),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("factory failed"));
    }

    #[tokio::test]
    async fn execute_with_store_rejects_invalid_target_before_storage() {
        let store = store(false);
        let error = StoreScanResults::execute_with_store(&store, &results(""))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("Invalid scan target"));
        assert!(store.persisted.lock().unwrap().is_empty());
    }
}
