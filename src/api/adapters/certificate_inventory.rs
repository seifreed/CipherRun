use crate::api::{models::error::ApiError, state::AppState};
use crate::application::{
    CertificateInventoryPage, CertificateInventoryPort, CertificateInventoryQuery,
    CertificateInventoryRecord,
};
use crate::db::CertificateInventoryService;

pub async fn load_inventory_page(
    reader: &impl CertificateInventoryPort,
    query: &CertificateInventoryQuery,
) -> Result<CertificateInventoryPage, ApiError> {
    reader.list_certificates(query).await.map_err(|error| {
        ApiError::internal_with_diagnostic("list_certificates", error.observability_code())
    })
}

pub async fn load_inventory_record(
    reader: &impl CertificateInventoryPort,
    fingerprint: &str,
) -> Result<Option<CertificateInventoryRecord>, ApiError> {
    reader.get_certificate(fingerprint).await.map_err(|error| {
        ApiError::internal_with_diagnostic("get_certificate", error.observability_code())
    })
}

pub async fn load_inventory_record_for_owner(
    reader: &impl CertificateInventoryPort,
    fingerprint: &str,
    principal_id: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<Option<CertificateInventoryRecord>, ApiError> {
    reader
        .get_certificate_for_owner(fingerprint, principal_id, tenant_id)
        .await
        .map_err(|error| {
            ApiError::internal_with_diagnostic(
                "get_certificate_for_owner",
                error.observability_code(),
            )
        })
}

pub fn inventory_service_from_state(
    state: &AppState,
) -> Result<CertificateInventoryService<'_>, ApiError> {
    let db_pool = state.db_pool.as_ref().ok_or_else(|| {
        ApiError::service_unavailable_with_diagnostic(
            "load_certificate_inventory",
            "database_not_configured",
        )
    })?;

    Ok(CertificateInventoryService::new(db_pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{api::config::ApiConfig, application::CertificateInventorySort};

    struct FailingInventory;

    #[async_trait::async_trait]
    impl CertificateInventoryPort for FailingInventory {
        async fn list_certificates(
            &self,
            _query: &CertificateInventoryQuery,
        ) -> crate::Result<CertificateInventoryPage> {
            Err(crate::TlsError::DatabaseError("private detail".into()))
        }

        async fn get_certificate(
            &self,
            _fingerprint: &str,
        ) -> crate::Result<Option<CertificateInventoryRecord>> {
            Err(crate::TlsError::DatabaseError("private detail".into()))
        }
    }

    #[tokio::test]
    async fn inventory_errors_are_mapped_to_safe_api_errors() {
        let query = CertificateInventoryQuery {
            limit: 10,
            offset: 0,
            sort: CertificateInventorySort::ExpiryAsc,
            hostname: None,
            expiring_within_days: None,
            principal_id: None,
            tenant_id: None,
        };

        let results = [
            load_inventory_page(&FailingInventory, &query)
                .await
                .map(|_| ()),
            load_inventory_record(&FailingInventory, "fingerprint")
                .await
                .map(|_| ()),
            load_inventory_record_for_owner(
                &FailingInventory,
                "fingerprint",
                Some("principal"),
                Some("tenant"),
            )
            .await
            .map(|_| ()),
        ];

        for result in results {
            let message = match result {
                Err(ApiError::Internal(message)) => message,
                _ => String::new(),
            };
            assert_eq!(message, "internal operation failed");
            assert!(!message.contains("private detail"));
        }
    }

    #[test]
    fn inventory_service_requires_database_configuration() {
        let state = AppState::new(ApiConfig::default()).expect("state should initialize");

        assert!(matches!(
            inventory_service_from_state(&state),
            Err(ApiError::ServiceUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn inventory_service_uses_configured_database() {
        let mut state = AppState::new(ApiConfig::default()).expect("state should initialize");
        let pool = sqlx::SqlitePool::connect(":memory:")
            .await
            .expect("in-memory database should connect");
        state.db_pool = Some(std::sync::Arc::new(crate::db::DatabasePool::Sqlite(pool)));

        assert!(inventory_service_from_state(&state).is_ok());
    }
}
