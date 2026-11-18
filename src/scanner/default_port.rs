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

#[cfg(test)]
mod tests {
    use super::DefaultScannerPort;
    use crate::application::{ScanRequest, ports::ScannerPort};

    #[tokio::test]
    async fn rejects_a_request_without_a_target() {
        let mut request = ScanRequest::default();
        request.scan.proto.tls12 = true;
        let error = DefaultScannerPort.scan(request).await.unwrap_err();

        assert!(error.to_string().contains("A target is required"));
    }

    #[tokio::test]
    async fn runs_a_scan_for_a_local_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut request = ScanRequest {
            target: Some("127.0.0.1".to_string()),
            port: Some(port),
            ..ScanRequest::default()
        };
        request.network.allow_private = true;
        request.scan.proto.tls12 = true;

        let result = DefaultScannerPort.scan(request).await.unwrap();

        assert_eq!(result.target, format!("127.0.0.1:{port}"));
    }
}
