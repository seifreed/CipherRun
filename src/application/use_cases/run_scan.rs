use crate::Result;
use crate::application::ScanRequest;
use crate::scanner::{ScanResults, Scanner};

/// Application use case for executing a TLS scan.
pub struct RunScan;

impl RunScan {
    pub async fn execute(request: ScanRequest) -> Result<ScanResults> {
        let scanner = Scanner::new(request)?;
        scanner.run().await
    }
}
