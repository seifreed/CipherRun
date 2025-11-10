// Authentication Middleware

use crate::api::{
    config::{ApiConfig, Permission},
    models::error::ApiError,
};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Authentication extension inserted into request
#[derive(Debug, Clone)]
pub struct AuthExtension {
    pub permission: Permission,
    pub api_key: String,
}

/// Authentication middleware
pub async fn authenticate(
    State(config): State<Arc<ApiConfig>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Skip authentication for health endpoint
    let path = req.uri().path();
    if path == "/api/v1/health" || path == "/health" {
        return Ok(next.run(req).await);
    }

    // Skip for Swagger UI
    if path.starts_with("/api/docs") || path.starts_with("/swagger") {
        return Ok(next.run(req).await);
    }

    // Extract API key from X-API-Key header
    let api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing X-API-Key header".to_string()))?;

    // Validate API key
    let permission = config
        .validate_key(api_key)
        .ok_or_else(|| ApiError::Unauthorized("Invalid API key".to_string()))?;

    // Store both permission and API key in request extensions for later use
    let auth_ext = AuthExtension {
        permission,
        api_key: api_key.to_string(),
    };
    req.extensions_mut().insert(auth_ext);

    Ok(next.run(req).await)
}

/// Check if user has required permission
pub fn check_permission(
    required: Permission,
    user_permission: Permission,
) -> Result<(), ApiError> {
    let allowed = match required {
        Permission::ReadOnly => true, // All permissions can read
        Permission::User => matches!(user_permission, Permission::User | Permission::Admin),
        Permission::Admin => matches!(user_permission, Permission::Admin),
    };

    if allowed {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "Insufficient permissions".to_string(),
        ))
    }
}

/// Extract permission from request extensions
pub fn get_permission(req: &Request) -> Option<Permission> {
    req.extensions().get::<AuthExtension>().map(|ext| ext.permission)
}

/// Extract auth extension from request extensions
pub fn get_auth_extension(req: &Request) -> Option<AuthExtension> {
    req.extensions().get::<AuthExtension>().cloned()
}
