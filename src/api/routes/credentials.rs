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
        other => ApiError::Internal(other.to_string()),
    }
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
    Extension(_auth): Extension<crate::api::middleware::AuthExtension>,
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
    Extension(_auth): Extension<crate::api::middleware::AuthExtension>,
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
    Extension(_auth): Extension<crate::api::middleware::AuthExtension>,
    Path(key_id): Path<String>,
) -> Result<Json<CredentialView>, ApiError> {
    let credential = state
        .credential_store
        .revoke(&key_id)
        .await
        .map_err(map_store_error)?;
    Ok(Json(view(credential)))
}
