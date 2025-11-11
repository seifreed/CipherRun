// OpenAPI Documentation

use crate::api::{
    models::{
        error::ApiErrorResponse,
        request::{PolicyRequest, ScanOptions, ScanRequest},
        response::{
            CertificateListResponse, HealthResponse, ScanResponse, ScanStatusResponse,
            StatsResponse,
        },
    },
    routes,
};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
};

/// OpenAPI documentation structure
#[derive(OpenApi)]
#[openapi(
    paths(
        routes::scans::create_scan,
        routes::scans::get_scan_status,
        routes::scans::get_scan_results,
        routes::scans::cancel_scan,
        routes::scans::websocket_handler,
        routes::certificates::list_certificates,
        routes::certificates::get_certificate,
        routes::compliance::check_compliance,
        routes::policies::create_policy,
        routes::policies::get_policy,
        routes::policies::evaluate_policy,
        routes::history::get_history,
        routes::stats::get_stats,
        routes::health::health_check,
    ),
    components(
        schemas(
            // Request models
            ScanRequest,
            ScanOptions,
            PolicyRequest,

            // Response models
            ScanResponse,
            ScanStatusResponse,
            HealthResponse,
            StatsResponse,
            CertificateListResponse,

            // Error model
            ApiErrorResponse,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "scans", description = "Scan management endpoints"),
        (name = "certificates", description = "Certificate inventory management"),
        (name = "compliance", description = "Compliance checking"),
        (name = "policies", description = "Policy management and evaluation"),
        (name = "history", description = "Scan history queries"),
        (name = "stats", description = "API statistics"),
        (name = "health", description = "Health check"),
    ),
    info(
        title = "CipherRun API",
        version = "1.0.0",
        description = r#"
# CipherRun REST API

A production-ready REST API for CipherRun, a comprehensive TLS/SSL security scanner.

## Features

- **Asynchronous Scans**: Queue scans and poll for status or use WebSockets for real-time updates
- **Certificate Inventory**: Track and monitor SSL/TLS certificates
- **Compliance Checking**: Verify configurations against industry standards
- **Policy Enforcement**: Define and evaluate custom security policies
- **Scan History**: Query historical scan data

## Authentication

All endpoints (except `/health`) require authentication via API key.

Pass the API key in the `X-API-Key` header:

```
X-API-Key: your-api-key-here
```

## Rate Limiting

API requests are rate limited to 100 requests per minute per API key.

## WebSocket Streaming

Real-time scan progress is available via WebSocket at `/api/v1/scan/{id}/stream`.

Connect to the WebSocket endpoint to receive JSON progress messages:

```json
{
  "msg_type": "progress",
  "scan_id": "uuid",
  "progress": 45,
  "stage": "testing_ciphers",
  "timestamp": "2025-11-09T12:00:00Z"
}
```
"#,
        contact(
            name = "CipherRun",
            url = "https://github.com/seifreed/cipherrun",
            email = "security@cipherrun.io"
        ),
        license(
            name = "GPL-3.0",
            url = "https://www.gnu.org/licenses/gpl-3.0.en.html"
        )
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development server"),
        (url = "https://api.cipherrun.io", description = "Production server")
    )
)]
pub struct ApiDoc;

/// Security scheme modifier
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
            )
        }
    }
}
