use crate::application::{ScanResultsStore, ScanResultsStoreFactory};
use crate::db::CipherRunDatabase;
use crate::utils::path_ext::PathExt;
use async_trait::async_trait;
use std::path::Path;

pub struct ConfigFileScanResultsStoreFactory;

#[async_trait]
impl ScanResultsStoreFactory for ConfigFileScanResultsStoreFactory {
    async fn open(&self, config_path: &Path) -> crate::Result<Box<dyn ScanResultsStore>> {
        let db = CipherRunDatabase::from_config_file(config_path.to_str_checked()?).await?;
        Ok(Box::new(db))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    #[tokio::test]
    async fn test_open_rejects_non_utf8_config_path() {
        let invalid = OsString::from_vec(vec![b'c', b'f', b'g', 0xff]);
        let factory = ConfigFileScanResultsStoreFactory;
        let err = match factory.open(&PathBuf::from(invalid)).await {
            Ok(_) => panic!("non-UTF-8 config path should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Invalid file path"));
    }
}
