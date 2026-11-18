use crate::application::{ScanResultsStore, ScanResultsStoreFactory};
use crate::db::CipherRunDatabase;
use async_trait::async_trait;
use std::path::Path;

pub struct ConfigFileScanResultsStoreFactory;

#[async_trait]
impl ScanResultsStoreFactory for ConfigFileScanResultsStoreFactory {
    async fn open(&self, config_path: &Path) -> crate::Result<Box<dyn ScanResultsStore>> {
        let db = CipherRunDatabase::from_config_file(config_path).await?;
        Ok(Box::new(db))
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigFileScanResultsStoreFactory;
    use crate::application::ScanResultsStoreFactory;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    #[tokio::test]
    async fn test_open_does_not_pre_reject_non_utf8_config_path() {
        let invalid = OsString::from_vec(vec![b'c', b'f', b'g', 0xff]);
        let factory = ConfigFileScanResultsStoreFactory;
        let err = factory
            .open(&PathBuf::from(invalid))
            .await
            .err()
            .expect("non-UTF-8 config path should fail");

        assert!(!err.to_string().contains("Invalid file path"));
    }

    #[tokio::test]
    async fn opens_a_store_from_a_valid_sqlite_config() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("database.toml");
        let config = crate::db::Config {
            database: crate::db::DatabaseConfig::sqlite(directory.path().join("scan.db")),
            retention: None,
        };
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

        let store = ConfigFileScanResultsStoreFactory
            .open(&config_path)
            .await
            .unwrap();

        drop(store);
        assert!(directory.path().join("scan.db").exists());
    }
}
