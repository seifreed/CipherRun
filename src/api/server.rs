// API Server Implementation

use crate::api::{
    config::ApiConfig,
    middleware,
    routes,
    state::AppState,
};
use anyhow::Result;
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tracing::info;

/// API Server
pub struct ApiServer {
    config: ApiConfig,
    state: Arc<AppState>,
}

impl ApiServer {
    /// Create new API server
    pub fn new(config: ApiConfig) -> Result<Self> {
        let state = Arc::new(AppState::new(config.clone())?);

        Ok(Self { config, state })
    }

    /// Build the router
    fn build_router(&self) -> Router {
        // Create API routes
        let api_routes = Router::new()
            // Scan routes
            .route("/scan", post(routes::scans::create_scan))
            .route("/scan/:id", get(routes::scans::get_scan_status))
            .route("/scan/:id", delete(routes::scans::cancel_scan))
            .route("/scan/:id/results", get(routes::scans::get_scan_results))
            .route("/scan/:id/stream", get(routes::scans::websocket_handler))
            // Certificate routes
            .route("/certificates", get(routes::certificates::list_certificates))
            .route(
                "/certificates/:fingerprint",
                get(routes::certificates::get_certificate),
            )
            // Compliance routes
            .route(
                "/compliance/:framework",
                get(routes::compliance::check_compliance),
            )
            // Policy routes
            .route("/policies", post(routes::policies::create_policy))
            .route("/policies/:id", get(routes::policies::get_policy))
            .route("/policies/:id/evaluate", post(routes::policies::evaluate_policy))
            // History routes
            .route("/history/:domain", get(routes::history::get_history))
            // Stats routes
            .route("/stats", get(routes::stats::get_stats))
            // Health check
            .route("/health", get(routes::health::health_check));

        // Build main router with versioning
        

        Router::new()
            .nest("/api/v1", api_routes)
            // Also support /health at root level
            .route("/health", get(routes::health::health_check))
            // Add OpenAPI/Swagger UI if enabled
            .merge(self.swagger_routes())
            // Add authentication middleware
            .layer(axum_middleware::from_fn_with_state(
                Arc::new(self.config.clone()),
                middleware::authenticate,
            ))
            // Add CORS
            .layer(middleware::cors_layer())
            // Add compression
            .layer(CompressionLayer::new())
            // Add logging
            .layer(middleware::logging_layer())
            // Add shared state
            .with_state(self.state.clone())
    }

    /// Build Swagger UI routes
    fn swagger_routes(&self) -> Router<Arc<AppState>> {
        if self.config.enable_swagger {
            use utoipa::OpenApi;
            use utoipa_swagger_ui::SwaggerUi;

            let openapi = crate::api::openapi::ApiDoc::openapi();

            Router::new().merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", openapi))
        } else {
            Router::new()
        }
    }

    /// Run the server
    pub async fn run(self) -> Result<()> {
        // Start the executor
        let state = self.state.clone();
        state.start_executor().await?;

        // Build router
        let app = self.build_router();

        // Create listener
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;

        info!("CipherRun API server listening on {}", addr);
        info!("OpenAPI documentation available at: http://{}/api/docs", addr);
        info!("Health check endpoint: http://{}/health", addr);

        // Serve
        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Get the application state
    pub fn state(&self) -> Arc<AppState> {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config);
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_router_build() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config).unwrap();
        let _router = server.build_router();
        // Just verify it builds without panicking
    }
}
