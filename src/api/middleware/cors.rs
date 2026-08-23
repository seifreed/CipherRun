// CORS Middleware

use axum::http::{HeaderValue, header};
use tower_http::cors::CorsLayer;

/// Create CORS layer with specific origins for production
pub fn cors_layer_with_origins(origins: Vec<String>) -> crate::Result<CorsLayer> {
    use axum::http::Method;
    use tower_http::cors::AllowOrigin;

    let allow_origins: Vec<HeaderValue> = origins
        .iter()
        .map(|origin| {
            let url = url::Url::parse(origin).map_err(|error| crate::TlsError::InvalidInput {
                message: format!("Invalid CORS origin '{origin}': {error}"),
            })?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(crate::TlsError::InvalidInput {
                    message: format!("Invalid CORS origin '{origin}': expected an HTTP(S) origin"),
                });
            }
            origin
                .parse()
                .map_err(|error| crate::TlsError::InvalidInput {
                    message: format!("Invalid CORS origin '{origin}': {error}"),
                })
        })
        .collect::<crate::Result<_>>()?;

    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(allow_origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-api-key"),
        ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::{Router, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_cors_layer_with_origins_allows_match() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors_layer_with_origins(vec!["https://example.com".to_string()]).unwrap());

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
            .layer(cors_layer_with_origins(vec!["https://example.com".to_string()]).unwrap());

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
            .layer(cors_layer_with_origins(Vec::new()).unwrap());

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

    #[test]
    fn test_cors_layer_with_origins_rejects_invalid_origin() {
        let error = match cors_layer_with_origins(vec!["https://example.com\n".to_string()]) {
            Ok(_) => panic!("expected invalid CORS origin to fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("Invalid CORS origin"));
    }

    #[test]
    fn test_cors_layer_with_origins_rejects_url_instead_of_origin() {
        let error =
            match cors_layer_with_origins(vec!["https://example.com/path?query=value".to_string()])
            {
                Ok(_) => panic!("expected URL with path to fail"),
                Err(error) => error,
            };

        assert!(error.to_string().contains("expected an HTTP(S) origin"));
    }
}
