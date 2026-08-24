// API Server Implementation

use crate::Result;
use crate::api::{
    config::{ApiConfig, JobBackend},
    jobs::DatabaseJobQueue,
    middleware,
    models::error::ApiError,
    routes,
    state::AppState,
};
use crate::utils::network::canonical_target;
use axum::{
    Router,
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, connect_info::Connected},
    middleware as axum_middleware,
    routing::{delete, get, post},
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tower::{BoxError, ServiceBuilder};
use tower_http::compression::CompressionLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

#[derive(Clone, Copy)]
pub(crate) struct PeerAddr(pub(crate) std::net::SocketAddr);

struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!("TLS listener accept failed: {error}");
                    continue;
                }
            };
            match self.acceptor.accept(stream).await {
                Ok(stream) => return (stream, address),
                Err(error) => tracing::warn!(%address, "TLS handshake failed: {error}"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

impl Connected<axum::serve::IncomingStream<'_, TcpListener>> for PeerAddr {
    fn connect_info(stream: axum::serve::IncomingStream<'_, TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Connected<axum::serve::IncomingStream<'_, TlsListener>> for PeerAddr {
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

fn load_api_tls_config(
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
    client_ca_file: Option<&std::path::Path>,
) -> Result<rustls::ServerConfig> {
    let material = crate::utils::mtls::MtlsConfig::from_separate_files(cert_file, key_file, None)
        .map_err(|error| crate::error::TlsError::ConfigError {
        message: format!("Failed to load API TLS material: {error}"),
    })?;
    let builder = if let Some(ca_file) = client_ca_file {
        let ca_bytes =
            std::fs::read(ca_file).map_err(|error| crate::error::TlsError::ConfigError {
                message: format!("Failed to read API TLS client CA: {error}"),
            })?;
        let mut roots = rustls::RootCertStore::empty();
        let mut found = 0usize;
        for item in
            pem::parse_many(ca_bytes).map_err(|error| crate::error::TlsError::ConfigError {
                message: format!("Failed to parse API TLS client CA: {error}"),
            })?
        {
            if item.tag() == "CERTIFICATE" {
                roots
                    .add(rustls::pki_types::CertificateDer::from(
                        item.into_contents(),
                    ))
                    .map_err(|error| crate::error::TlsError::ConfigError {
                        message: format!("Invalid API TLS client CA: {error}"),
                    })?;
                found += 1;
            }
        }
        if found == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "API TLS client CA file contains no certificates".to_string(),
            });
        }
        rustls::ServerConfig::builder().with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|error| crate::error::TlsError::ConfigError {
                    message: format!("Invalid API TLS client verifier: {error}"),
                })?,
        )
    } else {
        rustls::ServerConfig::builder().with_no_client_auth()
    };
    builder
        .with_single_cert(material.cert_chain, material.private_key)
        .map_err(|error| crate::error::TlsError::ConfigError {
            message: format!("Invalid API TLS material: {error}"),
        })
}

/// API Server
pub struct ApiServer {
    config: ApiConfig,
    state: Arc<AppState>,
}

async fn handle_timeout_error(error: BoxError) -> ApiError {
    if error.is::<tower::timeout::error::Elapsed>() {
        ApiError::Timeout("Request timed out".to_string())
    } else {
        ApiError::Internal(format!("Unhandled middleware error: {error}"))
    }
}

impl ApiServer {
    /// Create new API server without database persistence.
    ///
    /// History, certificate-inventory and stats endpoints will report 503
    /// Service Unavailable until a pool is supplied via [`Self::with_db_pool`].
    pub fn new(config: ApiConfig) -> Result<Self> {
        Self::with_db_pool(config, None)
    }

    /// Create a new API server with an optional database pool attached.
    ///
    /// When `db_pool` is `Some`, the database-backed endpoints (history,
    /// certificate inventory, stats persistence) become available. The
    /// `--serve --db-config <file>` invocation supplies the pool.
    pub fn with_db_pool(
        config: ApiConfig,
        db_pool: Option<Arc<crate::db::DatabasePool>>,
    ) -> Result<Self> {
        let mut state = AppState::new(config.clone())?;
        state.db_pool = db_pool;
        if let Some(pool) = &state.db_pool {
            state.replace_results_store(Arc::new(pool.as_ref().clone()));
        }
        if config.job_backend == JobBackend::Database {
            let pool =
                state
                    .db_pool
                    .clone()
                    .ok_or_else(|| crate::error::TlsError::ConfigError {
                        message: "database job backend requires a configured database pool"
                            .to_string(),
                    })?;
            let retention = i64::try_from(config.job_retention_seconds)
                .ok()
                .map(chrono::Duration::seconds);
            state.replace_job_queue(DatabaseJobQueue::new(
                pool,
                config.job_queue_capacity,
                retention,
            ));
        }

        Ok(Self {
            config,
            state: Arc::new(state),
        })
    }

    /// Build the router
    fn build_router(&self) -> Result<Router> {
        // Create API routes
        let api_routes = Router::new()
            // Scan routes — create/cancel are write actions and require at least
            // User permission; status/results/stream are reads (ReadOnly allowed).
            .route(
                "/scan",
                post(routes::scans::create_scan)
                    .layer(axum_middleware::from_fn(middleware::require_user)),
            )
            .route("/scan/{id}", get(routes::scans::get_scan_status))
            .route(
                "/scan/{id}",
                delete(routes::scans::cancel_scan)
                    .layer(axum_middleware::from_fn(middleware::require_user)),
            )
            .route("/scan/{id}/results", get(routes::scans::get_scan_results))
            .route("/scan/{id}/stream", get(routes::scans::websocket_handler))
            .route(
                "/scan/{id}/stream-ticket",
                post(routes::scans::create_stream_ticket),
            )
            // Credential lifecycle is restricted to administrators and never
            // returns a stored hash or an existing secret.
            .route(
                "/credentials",
                get(routes::credentials::list_credentials)
                    .post(routes::credentials::create_credential)
                    .layer(axum_middleware::from_fn(middleware::require_admin)),
            )
            .route(
                "/credentials/{key_id}/rotate",
                post(routes::credentials::rotate_credential)
                    .layer(axum_middleware::from_fn(middleware::require_admin)),
            )
            .route(
                "/credentials/{key_id}/revoke",
                post(routes::credentials::revoke_credential)
                    .layer(axum_middleware::from_fn(middleware::require_admin)),
            )
            // Certificate routes
            .route(
                "/certificates",
                get(routes::certificates::list_certificates_for_auth)
                    .layer(axum_middleware::from_fn(middleware::require_user)),
            )
            .route(
                "/certificates/{fingerprint}",
                get(routes::certificates::get_certificate_for_auth)
                    .layer(axum_middleware::from_fn(middleware::require_user)),
            )
            // Compliance routes
            .route(
                "/compliance/{framework}",
                get(routes::compliance::check_compliance),
            )
            // Policy routes — create/evaluate are write actions (User+); get is a read.
            .route(
                "/policies",
                post(routes::policies::create_policy)
                    .layer(axum_middleware::from_fn(middleware::require_user)),
            )
            .route("/policies/{id}", get(routes::policies::get_policy))
            .route(
                "/policies/{id}/evaluate",
                post(routes::policies::evaluate_policy)
                    .layer(axum_middleware::from_fn(middleware::require_user)),
            )
            // History routes
            .route(
                "/history/{domain}",
                get(routes::history::get_history_for_auth)
                    .layer(axum_middleware::from_fn(middleware::require_user)),
            )
            // Stats routes
            .route(
                "/stats",
                get(routes::stats::get_stats)
                    .layer(axum_middleware::from_fn(middleware::require_admin)),
            )
            .route("/metrics", get(routes::prometheus::metrics))
            // Health check
            .route("/health", get(routes::health::health_check));

        // Build main router with versioning
        // Note: Middleware layers are applied in reverse order in Axum
        let router = Router::new()
            .nest("/api/v1", api_routes)
            // Also support /health at root level
            .route("/health", get(routes::health::health_check))
            // Add OpenAPI/Swagger UI if enabled
            .merge(self.swagger_routes())
            // Add rate limiting middleware (runs after auth due to reverse order)
            .layer(axum_middleware::from_fn_with_state(
                self.state.clone(),
                middleware::rate_limit,
            ))
            // Add authentication middleware (runs first due to reverse order)
            .layer(axum_middleware::from_fn_with_state(
                self.state.credential_store.clone(),
                middleware::authenticate,
            ))
            .layer(axum_middleware::from_fn_with_state(
                self.state.clone(),
                middleware::metrics,
            ));

        // CORS is opt-in and only permits explicitly configured origins.
        let mut router = if self.config.enable_cors {
            router.layer(middleware::cors_layer_with_origins(
                self.config.allowed_origins.clone(),
            )?)
        } else {
            router
        };

        if self.config.tls_cert_file.is_some() {
            router = router.layer(SetResponseHeaderLayer::if_not_present(
                axum::http::header::STRICT_TRANSPORT_SECURITY,
                axum::http::HeaderValue::from_static("max-age=31536000"),
            ));
        }

        #[cfg(test)]
        let router = router.route(
            "/__test/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                "ok"
            }),
        );

        Ok(router
            // Enforce the configured JSON/body size limit for request extractors.
            .layer(DefaultBodyLimit::max(self.config.max_body_size))
            // Bound total request handling time using the configured API timeout.
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_timeout_error))
                    .timeout(Duration::from_secs(self.config.request_timeout_seconds)),
            )
            // Add compression
            .layer(CompressionLayer::new())
            // Add logging
            .layer(middleware::logging_layer())
            // Add shared state
            .with_state(self.state.clone()))
    }

    /// Build Swagger UI routes.
    ///
    /// Swagger UI is only available when the `swagger` cargo feature is enabled
    /// (it requires downloading the Swagger UI bundle at build time). When the
    /// feature is disabled, this is a no-op even if `enable_swagger` is set, so
    /// the rest of the API server builds and runs fully offline.
    fn swagger_routes(&self) -> Router<Arc<AppState>> {
        #[cfg(feature = "swagger")]
        {
            if self.config.enable_swagger {
                use utoipa::OpenApi;
                use utoipa_swagger_ui::SwaggerUi;

                let openapi = crate::api::openapi::ApiDoc::openapi();

                return Router::new()
                    .merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", openapi));
            }
        }
        #[cfg(not(feature = "swagger"))]
        {
            if self.config.enable_swagger {
                tracing::warn!(
                    "Swagger UI requested via config but the `swagger` cargo feature is not enabled; build with `--features swagger` to serve it."
                );
            }
        }
        Router::new()
    }

    /// Run the server
    pub async fn run(self) -> Result<()> {
        // API-only deployments can hand the shared database queue to external
        // workers instead of running a local executor.
        if self.config.local_executor {
            let state = self.state.clone();
            state.start_executor().await?;
        }

        // Build router
        let app = self.build_router()?;

        // Create listener
        let addr = canonical_target(&self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;

        let tls_enabled = self.config.tls_cert_file.is_some();
        info!(
            "CipherRun API server listening on {} ({})",
            addr,
            if tls_enabled { "HTTPS" } else { "HTTP" }
        );
        #[cfg(feature = "swagger")]
        if self.config.enable_swagger {
            info!(
                "OpenAPI documentation available at: http://{}/api/docs",
                addr
            );
        }
        info!("Health check endpoint: http://{}/health", addr);

        // Serve with native TLS when both certificate paths are configured.
        if let (Some(cert_file), Some(key_file)) =
            (&self.config.tls_cert_file, &self.config.tls_key_file)
        {
            let tls_config = load_api_tls_config(
                cert_file,
                key_file,
                self.config.tls_client_ca_file.as_deref(),
            )?;
            axum::serve(
                TlsListener {
                    listener,
                    acceptor: TlsAcceptor::from(Arc::new(tls_config)),
                },
                app.into_make_service_with_connect_info::<PeerAddr>(),
            )
            .await?;
        } else {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<PeerAddr>(),
            )
            .await?;
        }

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
    use crate::api::config::{JobBackend, Permission};
    use crate::api::jobs::ScanJob;
    use crate::db::{DatabaseConfig, DatabasePool};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[test]
    fn test_server_creation() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config);
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_database_job_backend_uses_attached_pool() {
        let directory = tempfile::tempdir().unwrap();
        let pool = DatabasePool::new(&DatabaseConfig::sqlite(directory.path().join("jobs.db")))
            .await
            .unwrap();
        let config = ApiConfig {
            job_backend: JobBackend::Database,
            ..Default::default()
        };
        let server = ApiServer::with_db_pool(config, Some(Arc::new(pool))).unwrap();
        let job = ScanJob::new("example.com:443".to_string(), Default::default(), None);
        let id = server.state().job_queue.enqueue(job).await.unwrap();
        assert!(
            server
                .state()
                .job_queue
                .get_job(&id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_database_job_backend_requires_pool() {
        let config = ApiConfig {
            job_backend: JobBackend::Database,
            ..Default::default()
        };
        let error = match ApiServer::new(config) {
            Ok(_) => panic!("database backend needs a pool"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("requires a configured database pool")
        );
    }

    #[tokio::test]
    async fn test_router_build() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config).expect("test assertion should succeed");
        let _router = server.build_router().expect("router should build");
        // Just verify it builds without panicking
    }

    #[tokio::test]
    async fn https_router_sets_hsts_header() {
        let config = ApiConfig {
            tls_cert_file: Some("/tmp/cipherrun-test-cert.pem".into()),
            tls_key_file: Some("/tmp/cipherrun-test-key.pem".into()),
            ..Default::default()
        };
        let app = ApiServer::new(config)
            .expect("server should build")
            .build_router()
            .expect("router should build");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(
            response
                .headers()
                .get("strict-transport-security")
                .and_then(|value| value.to_str().ok()),
            Some("max-age=31536000")
        );
    }

    #[tokio::test]
    async fn test_router_enforces_configured_body_limit() {
        let mut config = ApiConfig {
            max_body_size: 8,
            ..Default::default()
        };
        config.api_keys.clear();
        config
            .api_keys
            .insert("test-key".to_string(), Permission::User);

        let app = ApiServer::new(config)
            .expect("server should build")
            .build_router()
            .expect("router should build");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan")
                    .header("X-API-Key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"target":"example.com"}"#))
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_router_enforces_configured_request_timeout() {
        let config = ApiConfig {
            request_timeout_seconds: 1,
            ..Default::default()
        };

        let app = ApiServer::new(config)
            .expect("server should build")
            .build_router()
            .expect("router should build");
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/__test/slow")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }
}
