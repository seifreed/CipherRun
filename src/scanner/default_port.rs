use crate::application::ScanRequest;
use crate::application::ports::ScannerPort;
use crate::scanner::{ScanResults, Scanner};
use async_trait::async_trait;

/// Default ScannerPort implementation that creates and runs a Scanner directly.
pub struct DefaultScannerPort;

#[async_trait]
impl ScannerPort for DefaultScannerPort {
    async fn scan(&self, request: ScanRequest) -> crate::Result<ScanResults> {
        let scanner = Scanner::new(request)?;
        scanner.run().await
    }
}
