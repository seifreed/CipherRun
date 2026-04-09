use crate::Result;
use crate::application::{ScanRequest, ScanResults, ScannerPort};

/// Application use case for executing a TLS scan.
pub struct RunScan;

impl RunScan {
    /// Execute a scan using an injected scanner port.
    pub async fn execute(request: ScanRequest, scanner: &dyn ScannerPort) -> Result<ScanResults> {
        scanner.scan(request).await
    }
}
