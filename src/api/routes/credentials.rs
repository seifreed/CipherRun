use crate::api::{
    config::{ApiCredential, Permission},
    models::error::ApiError,
    state::AppState,
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

const MAX_CREDENTIAL_ID_BYTES: usize = 128;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCredentialRequest {
    pub key_id: String,
    pub principal_id: String,
    pub tenant_id: Option<String>,
    pub permission: Permission,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateCredentialRequest {
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialView {
    pub key_id: String,
    pub principal_id: String,
    pub tenant_id: Option<String>,
    pub permission: Permission,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialSecretResponse {
    pub credential: CredentialView,
    /// Returned only once during create/rotate; never persisted in API output.
    pub secret: String,
}

fn validate_identifier(value: &str, field: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_ID_BYTES
        || value.chars().any(char::is_whitespace)
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must be non-empty, contain no whitespace, and be at most {MAX_CREDENTIAL_ID_BYTES} bytes"
        )));
    }
    Ok(())
}

fn view(credential: ApiCredential) -> CredentialView {
    CredentialView {
        key_id: credential.key_id,
        principal_id: credential.principal_id,
        tenant_id: credential.tenant_id,
        permission: credential.permission,
        created_at: credential.created_at,
        expires_at: credential.expires_at,
        active: credential.active,
    }
}

fn map_store_error(error: crate::TlsError) -> ApiError {
    match error {
        crate::TlsError::InvalidInput { message } => ApiError::BadRequest(message),
        crate::TlsError::ConfigError { message } => ApiError::Conflict(message),
        other => ApiError::internal_with_diagnostic("credential_store", other.observability_code()),
    }
}

fn audit_credential_transition(
    event_name: &'static str,
    actor: Permission,
    credential: &ApiCredential,
) {
    tracing::info!(
        event_name,
        actor_permission = ?actor,
        credential_permission = ?credential.permission,
        tenant_scoped = credential.tenant_id.is_some(),
        "API credential access state changed"
    );
}

/// List credentials without exposing secret hashes.
#[utoipa::path(
    get,
    path = "/api/v1/credentials",
    tag = "credentials",
    responses((status = 200, description = "Credential metadata", body = [CredentialView])),
    security(("api_key" = []))
)]
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<crate::api::middleware::AuthExtension>,
) -> Result<Json<Vec<CredentialView>>, ApiError> {
    let credentials = state.credential_store.list().await;
    Ok(Json(credentials.into_iter().map(view).collect()))
}

/// Create a credential and return its one-time plaintext secret.
#[utoipa::path(
    post,
    path = "/api/v1/credentials",
    tag = "credentials",
    request_body = CreateCredentialRequest,
    responses((status = 201, description = "Credential created", body = CredentialSecretResponse)),
    security(("api_key" = []))
)]
pub async fn create_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<crate::api::middleware::AuthExtension>,
    Json(request): Json<CreateCredentialRequest>,
) -> Result<(StatusCode, Json<CredentialSecretResponse>), ApiError> {
    validate_identifier(&request.key_id, "key_id")?;
    validate_identifier(&request.principal_id, "principal_id")?;
    if let Some(tenant_id) = &request.tenant_id {
        validate_identifier(tenant_id, "tenant_id")?;
    }
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return Err(ApiError::BadRequest(
            "expires_at must be in the future".to_string(),
        ));
    }

    let secret = crate::api::config::generate_secure_api_key();
    let mut credential = ApiCredential::from_secret(
        request.key_id,
        &secret,
        request.principal_id,
        request.tenant_id,
        request.permission,
    );
    credential.expires_at = request.expires_at;
    state
        .credential_store
        .insert(credential.clone())
        .await
        .map_err(map_store_error)?;
    audit_credential_transition("security.credential.created", auth.permission, &credential);

    Ok((
        StatusCode::CREATED,
        Json(CredentialSecretResponse {
            credential: view(credential),
            secret,
        }),
    ))
}

/// Rotate a credential secret. The previous secret is invalid immediately.
#[utoipa::path(
    post,
    path = "/api/v1/credentials/{key_id}/rotate",
    tag = "credentials",
    params(("key_id" = String, Path, description = "Credential identifier")),
    request_body = RotateCredentialRequest,
    responses((status = 200, description = "Credential rotated", body = CredentialSecretResponse)),
    security(("api_key" = []))
)]
pub async fn rotate_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<crate::api::middleware::AuthExtension>,
    Path(key_id): Path<String>,
    Json(request): Json<RotateCredentialRequest>,
) -> Result<Json<CredentialSecretResponse>, ApiError> {
    let Some(expires_at) = request.expires_at else {
        let secret = crate::api::config::generate_secure_api_key();
        let credential = state
            .credential_store
            .rotate(&key_id, &secret, None)
            .await
            .map_err(map_store_error)?;
        audit_credential_transition("security.credential.rotated", auth.permission, &credential);
        return Ok(Json(CredentialSecretResponse {
            credential: view(credential),
            secret,
        }));
    };
    if expires_at <= Utc::now() {
        return Err(ApiError::BadRequest(
            "expires_at must be in the future".to_string(),
        ));
    }
    let secret = crate::api::config::generate_secure_api_key();
    let credential = state
        .credential_store
        .rotate(&key_id, &secret, Some(expires_at))
        .await
        .map_err(map_store_error)?;
    audit_credential_transition("security.credential.rotated", auth.permission, &credential);
    Ok(Json(CredentialSecretResponse {
        credential: view(credential),
        secret,
    }))
}

/// Revoke a credential immediately.
#[utoipa::path(
    post,
    path = "/api/v1/credentials/{key_id}/revoke",
    tag = "credentials",
    params(("key_id" = String, Path, description = "Credential identifier")),
    responses((status = 200, description = "Credential revoked", body = CredentialView)),
    security(("api_key" = []))
)]
pub async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<crate::api::middleware::AuthExtension>,
    Path(key_id): Path<String>,
) -> Result<Json<CredentialView>, ApiError> {
    let credential = state
        .credential_store
        .revoke(&key_id)
        .await
        .map_err(map_store_error)?;
    audit_credential_transition("security.credential.revoked", auth.permission, &credential);
    Ok(Json(view(credential)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{middleware::AuthExtension, test_support::build_test_state};
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedOutputWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedOutputWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedOutputWriter(self.0.clone())
        }
    }

    impl Write for CapturedOutputWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn credential_audit_events_exclude_ids_and_secret_hash() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(output.clone())
            .finish();
        let credential = ApiCredential {
            key_id: "sensitive-key-id".to_string(),
            secret_hash: "sensitive-secret-hash".to_string(),
            principal_id: "sensitive-principal-id".to_string(),
            tenant_id: Some("sensitive-tenant-id".to_string()),
            permission: Permission::User,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        };

        tracing::subscriber::with_default(subscriber, || {
            for event_name in [
                "security.credential.created",
                "security.credential.rotated",
                "security.credential.revoked",
            ] {
                audit_credential_transition(event_name, Permission::Admin, &credential);
            }
        });
        CapturedOutputWriter(output.0.clone())
            .flush()
            .expect("captured writer flush should succeed");

        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        for event_name in [
            "security.credential.created",
            "security.credential.rotated",
            "security.credential.revoked",
        ] {
            assert!(logs.contains(event_name));
        }
        assert!(logs.contains("actor_permission=Admin"));
        assert!(logs.contains("credential_permission=User"));
        assert!(logs.contains("tenant_scoped=true"));
        assert!(!logs.contains("sensitive-key-id"));
        assert!(!logs.contains("sensitive-secret-hash"));
        assert!(!logs.contains("sensitive-principal-id"));
        assert!(!logs.contains("sensitive-tenant-id"));
    }

    #[test]
    fn unexpected_store_errors_map_to_safe_internal_diagnostics() {
        let error = map_store_error(crate::TlsError::IoError {
            source: std::io::Error::other("secret filesystem detail"),
        });

        assert!(matches!(error, ApiError::Internal(_)));
        assert!(!error.to_string().contains("secret filesystem detail"));
    }

    #[tokio::test]
    async fn rotating_missing_credential_maps_store_errors_for_both_expiry_paths() {
        let state = build_test_state();
        let auth = || {
            Extension(AuthExtension {
                permission: Permission::Admin,
                key_id: "admin-key".to_string(),
                principal_id: "admin".to_string(),
                tenant_id: None,
            })
        };

        for expires_at in [None, Some(Utc::now() + chrono::Duration::days(1))] {
            let error = rotate_credential(
                State(state.clone()),
                auth(),
                axum::extract::Path("missing-key".to_string()),
                Json(RotateCredentialRequest { expires_at }),
            )
            .await
            .expect_err("rotating a missing credential should fail");

            assert!(matches!(error, ApiError::BadRequest(_)));
        }
    }
}
