// API Integration Tests

#[cfg(test)]
mod tests {
    use cipherrun::api::{ApiConfig, ApiServer};

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.port, 8080);
        assert_eq!(config.host, "0.0.0.0");
        assert!(config.enable_cors);
        assert!(config.max_concurrent_scans > 0);
    }

    #[test]
    fn test_api_server_creation() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config);
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_api_state_creation() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config).unwrap();
        let state = server.state();

        assert_eq!(state.uptime_seconds(), 0); // Just created
    }

    #[tokio::test]
    async fn test_job_queue() {
        use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue, ScanJob};
        use cipherrun::api::models::request::ScanOptions;

        let queue = InMemoryJobQueue::new(10);
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);

        let job_id = queue.enqueue(job.clone()).await.unwrap();
        assert_eq!(job_id, job.id);

        let retrieved = queue.get_job(&job_id).await.unwrap().unwrap();
        assert_eq!(retrieved.target, "example.com:443");
    }

    #[test]
    fn test_scan_options_full() {
        use cipherrun::api::models::request::ScanOptions;

        let options = ScanOptions::full();
        assert!(options.test_protocols);
        assert!(options.test_ciphers);
        assert!(options.test_vulnerabilities);
        assert!(options.analyze_certificates);
        assert!(options.test_http_headers);
        assert!(options.client_simulation);
        assert!(options.full_scan);
    }

    #[test]
    fn test_scan_options_quick() {
        use cipherrun::api::models::request::ScanOptions;

        let options = ScanOptions::quick();
        assert!(options.test_protocols);
        assert!(!options.test_ciphers);
        assert!(!options.test_vulnerabilities);
        assert!(options.analyze_certificates);
        assert!(!options.test_http_headers);
        assert!(!options.client_simulation);
        assert!(!options.full_scan);
    }

    #[test]
    fn test_api_error_status_codes() {
        use cipherrun::api::models::error::ApiError;
        use axum::http::StatusCode;

        assert_eq!(
            ApiError::BadRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Unauthorized("test".to_string()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::NotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::RateLimited("test".to_string()).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
