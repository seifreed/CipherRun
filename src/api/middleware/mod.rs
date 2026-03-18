// Middleware Module

pub mod auth;
pub mod cors;
pub mod logging;
pub mod metrics;
pub mod rate_limit;

pub use auth::{AuthExtension, authenticate, check_permission, get_auth_extension, get_permission};
pub use cors::cors_layer;
pub use logging::logging_layer;
pub use metrics::metrics;
pub use rate_limit::{PerKeyRateLimiter, rate_limit};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::Permission;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    #[test]
    fn test_check_permission_allows_and_denies() {
        assert!(check_permission(Permission::ReadOnly, Permission::User).is_ok());
        assert!(check_permission(Permission::Admin, Permission::Admin).is_ok());
        assert!(check_permission(Permission::Admin, Permission::User).is_err());
    }

    #[test]
    fn test_get_permission_and_auth_extension_from_mod() {
        let mut req = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request build");

        let auth = AuthExtension {
            permission: Permission::User,
            api_key: "key".to_string(),
        };
        req.extensions_mut().insert(auth.clone());

        let permission = get_permission(&req).expect("permission exists");
        assert_eq!(permission, Permission::User);

        let ext = get_auth_extension(&req).expect("auth ext exists");
        assert_eq!(ext.api_key, "key");
    }
}
