// Policy Routes

use super::policy_storage::{
    build_policy_content, policy_dir_from_state, read_policy_with_metadata, sanitized_policy_path,
};
use crate::api::{
    adapters::policy as policy_adapter,
    models::{
        error::{ApiError, ApiErrorResponse},
        request::{PolicyEvaluationRequest, PolicyRequest},
        response::{PolicyEvaluationResponse, PolicyResponse},
    },
    presenters::{
        policy::present_policy_evaluation,
        policy_response::{present_created_policy, present_loaded_policy},
        target_input::scan_request_from_target_and_options,
    },
    state::AppState,
};
use crate::application::PolicySource as _;
use crate::policy::FilesystemPolicySource;
use crate::policy::parser::PolicyLoader;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn existing_policy_path(policy_dir: &std::path::Path, id: &str) -> Result<PathBuf, ApiError> {
    let policy_path = sanitized_policy_path(policy_dir, id)?;
    if !policy_path.exists() {
        return Err(ApiError::NotFound(format!("Policy {} not found", id)));
    }

    Ok(policy_path)
}

/// Create or update policy
///
/// Creates a new policy or updates an existing one
#[utoipa::path(
    post,
    path = "/api/v1/policies",
    tag = "policies",
    request_body = PolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyResponse),
        (status = 400, description = "Invalid policy", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PolicyRequest>,
) -> Result<(StatusCode, Json<PolicyResponse>), ApiError> {
    let policy_dir = policy_dir_from_state(&state)?;

    fs::create_dir_all(policy_dir)
        .map_err(|e| ApiError::Internal(format!("Failed to create policy directory: {}", e)))?;

    // Validate policy YAML by parsing it
    PolicyLoader::load_from_string(&request.rules)
        .map_err(|e| ApiError::BadRequest(format!("Invalid policy YAML: {}", e)))?;

    let policy_id = sanitize_filename(&request.name);
    let policy_path = sanitized_policy_path(policy_dir, &policy_id).map_err(|e| match e {
        ApiError::BadRequest(_) => {
            ApiError::BadRequest(format!("Invalid policy filename: {}", policy_id))
        }
        other => other,
    })?;
    let now = Utc::now();
    let policy_content = build_policy_content(&request, now);

    fs::write(&policy_path, policy_content)
        .map_err(|e| ApiError::Internal(format!("Failed to write policy file: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(present_created_policy(policy_id, request, now)),
    ))
}

/// Get policy
///
/// Returns details of a specific policy
#[utoipa::path(
    get,
    path = "/api/v1/policies/{id}",
    tag = "policies",
    params(
        ("id" = String, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy details", body = PolicyResponse),
        (status = 404, description = "Policy not found", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy_dir = policy_dir_from_state(&state)?;
    let policy_path = existing_policy_path(policy_dir, &id)?;

    let (name, description, created_at, enabled, rules_content, updated_at) =
        read_policy_with_metadata(&policy_path, id.clone())?;

    Ok(Json(present_loaded_policy(
        id,
        name,
        description,
        rules_content,
        enabled,
        created_at,
        updated_at,
    )))
}

/// Evaluate policy
///
/// Evaluates a target against a specific policy
#[utoipa::path(
    post,
    path = "/api/v1/policies/{id}/evaluate",
    tag = "policies",
    params(
        ("id" = String, Path, description = "Policy ID")
    ),
    request_body = PolicyEvaluationRequest,
    responses(
        (status = 200, description = "Policy evaluation result", body = PolicyEvaluationResponse),
        (status = 400, description = "Invalid target or scan options", body = ApiErrorResponse),
        (status = 404, description = "Policy not found", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn evaluate_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(request): Json<PolicyEvaluationRequest>,
) -> Result<Json<PolicyEvaluationResponse>, ApiError> {
    let policy_dir = policy_dir_from_state(&state)?;
    let policy_path = existing_policy_path(policy_dir, &id)?;

    let policy = FilesystemPolicySource
        .load_policy(&policy_path)
        .map_err(|e| ApiError::Internal(format!("Failed to load policy: {}", e)))?;

    let scan_request = scan_request_from_target_and_options(&request.target, &request.options)?;

    let (scan_results, policy_result) =
        policy_adapter::run_policy_check_with_defaults(&policy, scan_request).await?;

    Ok(Json(present_policy_evaluation(
        id,
        policy.name,
        scan_results.target.clone(),
        &policy_result,
    )))
}

/// Sanitize filename to make it safe for filesystem
///
/// SECURITY: This only sanitizes the filename portion, not the full path.
/// For full path safety, use sanitize_path() which prevents traversal.
fn sanitize_filename(name: &str) -> String {
    // Remove any path separators
    let name = name.replace(['/', '\\'], "_");

    // Remove null bytes
    let name = name.replace('\0', "");

    // Convert to safe characters
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else if c.is_whitespace() {
                '-'
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::api::jobs::{InMemoryJobQueue, ScanExecutor};
    use crate::api::middleware::rate_limit::PerKeyRateLimiter;
    use crate::api::models::request::{PolicyEvaluationRequest, PolicyRequest};
    use crate::api::routes::policy_storage::parse_policy_file_content;
    use crate::api::state::{ApiStats, AppState};
    use axum::Json;
    use axum::extract::{Path, State};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::RwLock;

    fn build_state(policy_dir: PathBuf) -> Arc<AppState> {
        let config = Arc::new(ApiConfig::default());
        let job_queue = Arc::new(InMemoryJobQueue::new(10));
        let executor = Arc::new(ScanExecutor::new(job_queue.clone(), 1));
        let progress_tx = executor.progress_broadcaster();

        Arc::new(AppState {
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats: Arc::new(RwLock::new(ApiStats::default())),
            rate_limiter: Arc::new(PerKeyRateLimiter::new(100)),
            db_pool: None,
            policy_dir: Some(policy_dir),
        })
    }

    fn sample_policy_yaml() -> String {
        r#"
name: "Test Policy"
version: "1.0"
protocols:
  action: "FAIL"
  required:
    - "TLS1.2"
"#
        .trim()
        .to_string()
    }

    #[tokio::test]
    async fn test_create_and_get_policy() {
        let policy_dir = std::env::temp_dir().join("cipherrun_policy_tests");
        let _ = std::fs::remove_dir_all(&policy_dir);
        let state = build_state(policy_dir.clone());

        let request = PolicyRequest {
            name: "Test Policy".to_string(),
            description: Some("Test policy description".to_string()),
            rules: sample_policy_yaml(),
            enabled: true,
        };

        let (_, Json(created)) = create_policy(State(state.clone()), Json(request))
            .await
            .expect("policy creation should succeed");

        let fetched = get_policy(State(state), Path(created.id.clone()))
            .await
            .expect("policy fetch should succeed")
            .0;

        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.name, "Test Policy");
        assert!(fetched.rules.contains("protocols"));

        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[tokio::test]
    async fn test_create_policy_invalid_yaml() {
        let policy_dir = std::env::temp_dir().join("cipherrun_policy_tests_invalid");
        let _ = std::fs::remove_dir_all(&policy_dir);
        let state = build_state(policy_dir.clone());

        let request = PolicyRequest {
            name: "Broken Policy".to_string(),
            description: None,
            rules: "not: [valid".to_string(),
            enabled: true,
        };

        let err = create_policy(State(state), Json(request))
            .await
            .expect_err("invalid policy should error");

        assert!(matches!(err, ApiError::BadRequest(_)));
        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[tokio::test]
    async fn test_get_policy_missing() {
        let policy_dir = std::env::temp_dir().join("cipherrun_policy_tests_missing");
        let _ = std::fs::remove_dir_all(&policy_dir);
        std::fs::create_dir_all(&policy_dir).expect("policy dir should be created");
        let state = build_state(policy_dir.clone());

        let err = get_policy(State(state), Path("missing".to_string()))
            .await
            .expect_err("missing policy should error");

        assert!(matches!(err, ApiError::NotFound(_)));
        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[tokio::test]
    async fn test_evaluate_policy_rejects_empty_scan_options() {
        let policy_dir = std::env::temp_dir().join("cipherrun_policy_tests_evaluate_empty");
        let _ = std::fs::remove_dir_all(&policy_dir);
        let state = build_state(policy_dir.clone());

        let create_request = PolicyRequest {
            name: "Test Policy".to_string(),
            description: None,
            rules: sample_policy_yaml(),
            enabled: true,
        };
        let (_, Json(created)) = create_policy(State(state.clone()), Json(create_request))
            .await
            .expect("policy creation should succeed");

        let err = evaluate_policy(
            State(state),
            Path(created.id),
            Json(PolicyEvaluationRequest {
                target: "example.com:443".to_string(),
                options: Default::default(),
            }),
        )
        .await
        .expect_err("empty scan options should fail");

        assert!(matches!(err, ApiError::BadRequest(_)));
        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[tokio::test]
    async fn test_evaluate_policy_rejects_invalid_common_options() {
        let policy_dir = std::env::temp_dir().join("cipherrun_policy_tests_evaluate_invalid");
        let _ = std::fs::remove_dir_all(&policy_dir);
        let state = build_state(policy_dir.clone());

        let create_request = PolicyRequest {
            name: "Test Policy".to_string(),
            description: None,
            rules: sample_policy_yaml(),
            enabled: true,
        };
        let (_, Json(created)) = create_policy(State(state.clone()), Json(create_request))
            .await
            .expect("policy creation should succeed");

        let err = evaluate_policy(
            State(state),
            Path(created.id),
            Json(PolicyEvaluationRequest {
                target: "example.com:443".to_string(),
                options: crate::api::models::request::ScanOptions {
                    test_protocols: true,
                    timeout_seconds: 0,
                    ..Default::default()
                },
            }),
        )
        .await
        .expect_err("invalid scan options should fail");

        assert!(matches!(err, ApiError::BadRequest(_)));
        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[tokio::test]
    async fn test_evaluate_policy_maps_runtime_invalid_input_to_bad_request() {
        let policy_dir = std::env::temp_dir().join("cipherrun_policy_tests_evaluate_invalid_ip");
        let _ = std::fs::remove_dir_all(&policy_dir);
        let state = build_state(policy_dir.clone());

        let create_request = PolicyRequest {
            name: "Test Policy".to_string(),
            description: None,
            rules: sample_policy_yaml(),
            enabled: true,
        };
        let (_, Json(created)) = create_policy(State(state.clone()), Json(create_request))
            .await
            .expect("policy creation should succeed");

        let err = evaluate_policy(
            State(state),
            Path(created.id),
            Json(PolicyEvaluationRequest {
                target: "example.com:443".to_string(),
                options: crate::api::models::request::ScanOptions {
                    test_protocols: true,
                    ip: Some("not-an-ip".to_string()),
                    ..Default::default()
                },
            }),
        )
        .await
        .expect_err("invalid IP override should fail");

        assert!(matches!(err, ApiError::BadRequest(_)));
        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[tokio::test]
    async fn test_evaluate_policy_rejects_private_target() {
        let policy_dir = std::env::temp_dir().join("cipherrun_policy_tests_evaluate_private");
        let _ = std::fs::remove_dir_all(&policy_dir);
        let state = build_state(policy_dir.clone());

        let create_request = PolicyRequest {
            name: "Test Policy".to_string(),
            description: None,
            rules: sample_policy_yaml(),
            enabled: true,
        };
        let (_, Json(created)) = create_policy(State(state.clone()), Json(create_request))
            .await
            .expect("policy creation should succeed");

        let err = evaluate_policy(
            State(state),
            Path(created.id),
            Json(PolicyEvaluationRequest {
                target: "127.0.0.1:443".to_string(),
                options: crate::api::models::request::ScanOptions {
                    test_protocols: true,
                    ..Default::default()
                },
            }),
        )
        .await
        .expect_err("private target should fail");

        assert!(matches!(err, ApiError::BadRequest(_)));
        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[test]
    fn parses_policy_file_metadata() {
        let content = "# Policy: Test\n# Description: Desc\n# Created: 2025-01-01T00:00:00Z\n# Enabled: false\n\nrules:\n  - test\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Test");
        assert_eq!(description.as_deref(), Some("Desc"));
        assert!(!enabled);
        assert!(rules.contains("rules:"));
    }

    #[test]
    fn existing_policy_path_returns_not_found_for_missing_file() {
        let dir = std::env::temp_dir().join("cipherrun_policy_missing_helper");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("policy dir should be created");

        let err = existing_policy_path(&dir, "missing").expect_err("missing policy should error");
        assert!(matches!(err, ApiError::NotFound(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
