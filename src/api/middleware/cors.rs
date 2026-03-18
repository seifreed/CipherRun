// CORS Middleware

use tower_http::cors::{Any, CorsLayer};

/// Create CORS layer with permissive settings for development
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any)
}

/// Create CORS layer with specific origins for production
pub fn cors_layer_with_origins(origins: Vec<String>) -> CorsLayer {
    use axum::http::Method;
    use tower_http::cors::AllowOrigin;

    let allow_origins: Vec<_> = origins.iter().filter_map(|o| o.parse().ok()).collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allow_origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any)
        .expose_headers(Any)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::{Router, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_cors_layer_allows_any_origin() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors_layer());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .header("Origin", "https://example.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
    }

    #[tokio::test]
    async fn test_cors_layer_with_origins_allows_match() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors_layer_with_origins(vec![
                "https://example.com".to_string(),
            ]));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .header("Origin", "https://example.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn test_cors_layer_with_origins_rejects_unlisted_origin() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors_layer_with_origins(vec![
                "https://example.com".to_string(),
            ]));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .header("Origin", "https://not-allowed.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(headers.get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn test_cors_layer_with_empty_origins() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors_layer_with_origins(Vec::new()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .header("Origin", "https://example.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(headers.get("access-control-allow-origin").is_none());
    }
}
