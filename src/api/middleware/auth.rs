// Authentication Middleware

use crate::api::{
    config::{ApiConfig, Permission},
    models::error::ApiError,
};
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Authentication extension inserted into request
#[derive(Debug, Clone)]
pub struct AuthExtension {
    pub permission: Permission,
    pub key_id: String,
    pub principal_id: String,
    pub tenant_id: Option<String>,
}

fn api_key_from_query(query: &str) -> Result<Option<String>, ApiError> {
    let mut api_key = None;
    for param in query.split('&') {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        let key = decode_query_component(key)?;
        if key == "api_key" {
            if !param.contains('=') {
                return Err(ApiError::BadRequest(
                    "api_key query parameter must include a value".to_string(),
                ));
            }
            if api_key.is_some() {
                return Err(ApiError::BadRequest(
                    "Duplicate api_key query parameter".to_string(),
                ));
            }
            api_key = Some(decode_query_component(value)?);
        }
    }

    Ok(api_key)
}

fn is_stream_path(path: &str) -> bool {
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    matches!(segments.as_slice(), ["api", "v1", "scan", scan_id, "stream"] if !scan_id.is_empty())
}

fn stream_ticket_from_query(query: &str) -> Result<Option<String>, ApiError> {
    let mut ticket = None;
    for param in query.split('&') {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        if decode_query_component(key)? == "ticket" {
            if ticket.is_some() || value.is_empty() {
                return Err(ApiError::BadRequest(
                    "ticket query parameter must appear once with a value".to_string(),
                ));
            }
            ticket = Some(decode_query_component(value)?);
        }
    }
    Ok(ticket)
}

fn decode_query_component(value: &str) -> Result<String, ApiError> {
    let value = value.replace('+', " ");
    urlencoding::decode(&value)
        .map(|decoded| decoded.into_owned())
        .map_err(|error| ApiError::BadRequest(format!("Invalid query parameter encoding: {error}")))
}

fn api_key_from_headers(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let mut values = headers.get_all("X-API-Key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::BadRequest(
            "Duplicate X-API-Key header".to_string(),
        ));
    }

    value
        .to_str()
        .map(str::to_string)
        .map(Some)
        .map_err(|error| ApiError::BadRequest(format!("Invalid X-API-Key header: {error}")))
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
    if path == "/api/docs"
        || path.starts_with("/api/docs/")
        || path == "/swagger"
        || path.starts_with("/swagger/")
    {
        return Ok(next.run(req).await);
    }

    let query_api_key = req
        .uri()
        .query()
        .map(api_key_from_query)
        .transpose()?
        .flatten();
    if query_api_key.is_some() {
        return Err(ApiError::BadRequest(
            "api_key query authentication is no longer supported; use X-API-Key or a one-use stream ticket"
                .to_string(),
        ));
    }
    let stream_ticket = req
        .uri()
        .query()
        .map(stream_ticket_from_query)
        .transpose()?
        .flatten();
    if stream_ticket.is_some() {
        if !is_stream_path(path) {
            return Err(ApiError::BadRequest(
                "stream tickets are only supported for WebSocket stream endpoints".to_string(),
            ));
        }
        if query_api_key.is_some() || req.headers().contains_key("X-API-Key") {
            return Err(ApiError::BadRequest(
                "Use either a stream ticket or an API key, not both".to_string(),
            ));
        }
        return Ok(next.run(req).await);
    }

    let header_api_key = api_key_from_headers(req.headers())?;
    let api_key = if let Some(api_key) = header_api_key {
        api_key
    } else {
        return Err(ApiError::Unauthorized(
            "Missing API key (use X-API-Key header)".to_string(),
        ));
    };

    // Validate API key
    let authenticated = config
        .authenticate_key(&api_key)
        .ok_or_else(|| ApiError::Unauthorized("Invalid API key".to_string()))?;

    let auth_ext = AuthExtension {
        permission: authenticated.permission,
        key_id: authenticated.key_id,
        principal_id: authenticated.principal_id,
        tenant_id: authenticated.tenant_id,
    };
    req.extensions_mut().insert(auth_ext);

    Ok(next.run(req).await)
}

/// Route-level middleware enforcing at least `User` permission.
///
/// Applied to mutating/action endpoints (scan create/cancel, policy
/// create/evaluate) so a `ReadOnly` API key cannot perform them. Relies on
/// [`authenticate`] having already inserted the [`AuthExtension`]; a missing
/// extension means the request bypassed auth and is rejected.
pub async fn require_user(req: Request, next: Next) -> Result<Response, ApiError> {
    require_permission_level(Permission::User, req, next).await
}

/// Route-level middleware for global administrator-owned resources.
pub async fn require_admin(req: Request, next: Next) -> Result<Response, ApiError> {
    require_permission_level(Permission::Admin, req, next).await
}

async fn require_permission_level(
    required: Permission,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let permission = get_permission(&req)
        .ok_or_else(|| ApiError::Unauthorized("Missing authentication".to_string()))?;
    check_permission(required, permission)?;
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
    use axum::http::HeaderValue;
    use axum::http::Request as HttpRequest;

    #[test]
    fn test_get_permission_and_auth_extension() {
        let mut req = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request build");

        let auth = AuthExtension {
            permission: Permission::User,
            key_id: "key-id".to_string(),
            principal_id: "principal-id".to_string(),
            tenant_id: None,
        };
        req.extensions_mut().insert(auth.clone());

        let permission = get_permission(&req).expect("permission exists");
        assert_eq!(permission, Permission::User);

        let ext = get_auth_extension(&req).expect("auth ext exists");
        assert_eq!(ext.key_id, "key-id");
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

    #[test]
    fn test_api_key_from_query_decodes_valid_key() {
        let key = api_key_from_query("foo=bar&api_key=a%2Bb")
            .expect("valid query should parse")
            .expect("api key should exist");

        assert_eq!(key, "a+b");
    }

    #[test]
    fn test_api_key_from_query_uses_form_url_encoding() {
        let key = api_key_from_query("api%5Fkey=a+b")
            .expect("valid query should parse")
            .expect("api key should exist");

        assert_eq!(key, "a b");
    }

    #[test]
    fn test_api_key_from_query_returns_none_when_absent() {
        assert!(
            api_key_from_query("foo=bar")
                .expect("valid query should parse")
                .is_none()
        );
    }

    #[test]
    fn test_api_key_from_query_rejects_invalid_encoding() {
        let err = api_key_from_query("api_key=%FF").expect_err("invalid encoding should fail");

        assert!(err.to_string().contains("Invalid query parameter encoding"));
    }

    #[test]
    fn test_api_key_from_query_rejects_duplicate_keys() {
        let err = api_key_from_query("api_key=one&api_key=two")
            .expect_err("duplicate api keys should fail");

        assert!(err.to_string().contains("Duplicate api_key"));
    }

    #[test]
    fn test_api_key_from_query_rejects_missing_value_separator() {
        let err = api_key_from_query("api_key").expect_err("malformed api_key should fail");

        assert!(err.to_string().contains("must include a value"));
    }

    #[test]
    fn test_stream_path_requires_exact_route() {
        assert!(is_stream_path("/api/v1/scan/scan-id/stream"));
        assert!(!is_stream_path("/api/v1/stats"));
        assert!(!is_stream_path("/api/v1/scan//stream"));
        assert!(!is_stream_path("/api/v1/scan/scan-id/results/stream"));
    }

    #[test]
    fn test_api_key_from_headers_rejects_invalid_header_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-API-Key",
            HeaderValue::from_bytes(&[0xff]).expect("opaque header bytes should build"),
        );

        let err = api_key_from_headers(&headers).expect_err("invalid header should fail");

        assert!(err.to_string().contains("Invalid X-API-Key header"));
    }

    #[test]
    fn test_api_key_from_headers_rejects_duplicate_headers() {
        let mut headers = HeaderMap::new();
        headers.append("X-API-Key", HeaderValue::from_static("one"));
        headers.append("X-API-Key", HeaderValue::from_static("two"));

        let err = api_key_from_headers(&headers).expect_err("duplicate headers should fail");

        assert!(err.to_string().contains("Duplicate X-API-Key"));
    }
}
