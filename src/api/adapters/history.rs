use crate::api::{models::error::ApiError, state::AppState};
use crate::application::{ScanHistoryPage, ScanHistoryPort, ScanHistoryQuery};
use crate::db::ScanHistoryService;

pub async fn load_scan_history(
    reader: &impl ScanHistoryPort,
    query: &ScanHistoryQuery,
) -> Result<ScanHistoryPage, ApiError> {
    reader.get_history(query).await.map_err(|error| {
        ApiError::internal_with_diagnostic("load_scan_history", error.observability_code())
    })
}

pub fn history_service_from_state(state: &AppState) -> Result<ScanHistoryService<'_>, ApiError> {
    let db_pool = state.db_pool.as_ref().ok_or_else(|| {
        ApiError::service_unavailable_with_diagnostic(
            "load_scan_history",
            "database_not_configured",
        )
    })?;

    Ok(ScanHistoryService::new(db_pool))
}

#[cfg(test)]
mod tests {
    use super::{history_service_from_state, load_scan_history};
    use crate::api::{config::ApiConfig, models::error::ApiError, state::AppState};
    use crate::application::{ScanHistoryPage, ScanHistoryPort, ScanHistoryQuery};
    use async_trait::async_trait;

    struct FailingHistoryReader;

    #[async_trait]
    impl ScanHistoryPort for FailingHistoryReader {
        async fn get_history(&self, _query: &ScanHistoryQuery) -> crate::Result<ScanHistoryPage> {
            Err(crate::TlsError::Other("history backend failed".to_string()))
        }
    }

    #[tokio::test]
    async fn maps_history_reader_error_to_internal_error() {
        let query = ScanHistoryQuery {
            hostname: "example.com".to_string(),
            port: 443,
            limit: 10,
            principal_id: None,
            tenant_id: None,
        };
        let error = load_scan_history(&FailingHistoryReader, &query)
            .await
            .expect_err("reader failure should be returned");

        assert!(matches!(error, ApiError::Internal(_)));
    }

    #[test]
    fn reports_missing_database_configuration() {
        let state = AppState::new(ApiConfig::default()).expect("state should initialize");

        let error = history_service_from_state(&state)
            .err()
            .expect("history requires a configured database");

        assert!(matches!(error, ApiError::ServiceUnavailable(_)));
    }

    #[tokio::test]
    async fn creates_history_service_when_database_is_configured() {
        let mut state = AppState::new(ApiConfig::default()).expect("state should initialize");
        let pool = sqlx::SqlitePool::connect(":memory:")
            .await
            .expect("in-memory database should connect");
        state.db_pool = Some(std::sync::Arc::new(crate::db::DatabasePool::Sqlite(pool)));

        assert!(history_service_from_state(&state).is_ok());
    }
}
