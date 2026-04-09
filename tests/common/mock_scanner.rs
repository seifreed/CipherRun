use async_trait::async_trait;
use cipherrun::application::ScanRequest;
use cipherrun::application::ports::ScannerPort;
use cipherrun::scanner::ScanResults;

#[allow(dead_code)]
/// Mock scanner that returns predetermined results for testing.
pub struct MockScannerPort {
    pub results: ScanResults,
}

impl MockScannerPort {
    #[allow(dead_code)]
    pub fn default_success() -> Self {
        Self {
            results: ScanResults {
                target: "mock.example.com:443".to_string(),
                scan_time_ms: 100,
                ..Default::default()
            },
        }
    }
}

#[async_trait]
impl ScannerPort for MockScannerPort {
    async fn scan(&self, _request: ScanRequest) -> cipherrun::Result<ScanResults> {
        Ok(self.results.clone())
    }
}
