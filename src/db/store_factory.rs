use crate::application::{ScanResultsStore, ScanResultsStoreFactory};
use crate::db::CipherRunDatabase;
use async_trait::async_trait;
use std::path::Path;

pub struct ConfigFileScanResultsStoreFactory;

#[async_trait]
impl ScanResultsStoreFactory for ConfigFileScanResultsStoreFactory {
    async fn open(&self, config_path: &Path) -> crate::Result<Box<dyn ScanResultsStore>> {
        let db =
            CipherRunDatabase::from_config_file(config_path.to_string_lossy().as_ref()).await?;
        Ok(Box::new(db))
    }
}
