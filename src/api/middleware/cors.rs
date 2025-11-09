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

    let allow_origins: Vec<_> = origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

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
