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
    /// Whether the API key was provided via query parameter (less secure than header)
    pub from_query_param: bool,
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

    // Extract API key from X-API-Key header or query parameter
    // Query parameter support is needed for WebSocket connections from browsers
    // which cannot set custom headers during the WebSocket handshake
    // SECURITY NOTE: Query parameters are logged in server logs, proxy logs,
    // and browser history. Use X-API-Key header when possible.
    let (api_key, from_query_param) = req
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .map(|s| (s.to_string(), false))
        .or_else(|| {
            req.uri().query().and_then(|query| {
                query.split('&').find_map(|param| {
                    let parts: Vec<&str> = param.splitn(2, '=').collect();
                    if parts.len() == 2 && parts[0] == "api_key" {
                        let decoded = urlencoding::decode(parts[1])
                            .map(|s| s.to_string())
                            .unwrap_or_else(|_| parts[1].to_string());
                        Some((decoded, true))
                    } else {
                        None
                    }
                })
            })
        })
        .ok_or_else(|| {
            ApiError::Unauthorized(
                "Missing API key (use X-API-Key header or api_key query parameter)".to_string(),
            )
        })?;

    // SECURITY AUDIT: Log when API key is provided via query parameter
    // This is less secure than header-based auth and should be monitored
    if from_query_param {
        tracing::warn!(
            "SECURITY: API key provided via query parameter (less secure). \
             Key may be logged in server logs, proxy logs, and browser history. \
             Path: {}",
            path
        );
    }

    // Validate API key
    let permission = config
        .validate_key(&api_key)
        .ok_or_else(|| ApiError::Unauthorized("Invalid API key".to_string()))?;

    // Store both permission and API key in request extensions for later use
    let auth_ext = AuthExtension {
        permission,
        api_key: api_key.to_string(),
        from_query_param,
    };
    req.extensions_mut().insert(auth_ext);

    Ok(next.run(req).await)
}

/// Check if user has required permission
pub fn check_permission(required: Permission, user_permission: Permission) -> Result<(), ApiError> {
    let allowed = match required {
        Permission::ReadOnly => true, // All permissions can read
        Permission::User => matches!(user_permission, Permission::User | Permission::Admin),
        Permission::Admin => matches!(user_permission, Permission::Admin),
    };

    if allowed {
        Ok(())
    } else {
        Err(ApiError::Forbidden("Insufficient permissions".to_string()))
    }
}

/// Extract permission from request extensions
pub fn get_permission(req: &Request) -> Option<Permission> {
    req.extensions()
        .get::<AuthExtension>()
        .map(|ext| ext.permission)
}

/// Extract auth extension from request extensions
pub fn get_auth_extension(req: &Request) -> Option<AuthExtension> {
    req.extensions().get::<AuthExtension>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::Permission;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    #[test]
    fn test_get_permission_and_auth_extension() {
        let mut req = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request build");

        let auth = AuthExtension {
            permission: Permission::User,
            api_key: "key".to_string(),
            from_query_param: false,
        };
        req.extensions_mut().insert(auth.clone());

        let permission = get_permission(&req).expect("permission exists");
        assert_eq!(permission, Permission::User);

        let ext = get_auth_extension(&req).expect("auth ext exists");
        assert_eq!(ext.api_key, "key");
    }

    #[test]
    fn test_get_permission_none_when_missing() {
        let req = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request build");
        assert!(get_permission(&req).is_none());
        assert!(get_auth_extension(&req).is_none());
    }
}
