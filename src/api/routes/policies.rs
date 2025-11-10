// Policy Routes

use crate::api::{
    models::{
        error::{ApiError, ApiErrorResponse},
        request::{PolicyEvaluationRequest, PolicyRequest},
        response::{PolicyCheckResult, PolicyEvaluationResponse, PolicyResponse},
    },
    state::AppState,
};
use crate::policy::parser::PolicyLoader;
use crate::policy::evaluator::PolicyEvaluator;
use crate::scanner::Scanner;
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use std::fs;
use std::sync::Arc;
use uuid::Uuid;

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
) -> Result<Json<PolicyResponse>, ApiError> {
    // Get policy directory
    let policy_dir = state
        .policy_dir
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Policy storage not configured".to_string()))?;

    // Ensure policy directory exists
    fs::create_dir_all(policy_dir)
        .map_err(|e| ApiError::Internal(format!("Failed to create policy directory: {}", e)))?;

    // Validate policy YAML by parsing it
    PolicyLoader::load_from_string(&request.rules)
        .map_err(|e| ApiError::BadRequest(format!("Invalid policy YAML: {}", e)))?;

    // Generate policy ID (use name as filename-safe ID)
    let policy_id = sanitize_filename(&request.name);

    // Save policy to filesystem
    let policy_path = policy_dir.join(format!("{}.yaml", policy_id));

    // Create policy file with metadata
    let policy_content = format!(
        "# Policy: {}\n# Description: {}\n# Created: {}\n# Enabled: {}\n\n{}",
        request.name,
        request.description.as_ref().unwrap_or(&"No description".to_string()),
        Utc::now().to_rfc3339(),
        request.enabled,
        request.rules
    );

    fs::write(&policy_path, policy_content)
        .map_err(|e| ApiError::Internal(format!("Failed to write policy file: {}", e)))?;

    // Return policy response
    Ok(Json(PolicyResponse {
        id: policy_id,
        name: request.name,
        description: request.description,
        rules: request.rules,
        enabled: request.enabled,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
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
    // Get policy directory
    let policy_dir = state
        .policy_dir
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Policy storage not configured".to_string()))?;

    // Read policy file
    let policy_path = policy_dir.join(format!("{}.yaml", id));

    if !policy_path.exists() {
        return Err(ApiError::NotFound(format!("Policy {} not found", id)));
    }

    let content = fs::read_to_string(&policy_path)
        .map_err(|e| ApiError::Internal(format!("Failed to read policy file: {}", e)))?;

    // Extract metadata from comments
    let mut name = id.clone();
    let mut description = None;
    let mut created_at = Utc::now();
    let mut enabled = true;
    let mut rules_content = String::new();
    let mut in_metadata = true;

    for line in content.lines() {
        if in_metadata && line.starts_with("# Policy: ") {
            name = line.trim_start_matches("# Policy: ").to_string();
        } else if in_metadata && line.starts_with("# Description: ") {
            let desc = line.trim_start_matches("# Description: ").to_string();
            if desc != "No description" {
                description = Some(desc);
            }
        } else if in_metadata && line.starts_with("# Created: ") {
            let date_str = line.trim_start_matches("# Created: ");
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date_str) {
                created_at = dt.with_timezone(&Utc);
            }
        } else if in_metadata && line.starts_with("# Enabled: ") {
            enabled = line.trim_start_matches("# Enabled: ") == "true";
        } else if !line.starts_with('#') {
            in_metadata = false;
            if !line.trim().is_empty() {
                rules_content.push_str(line);
                rules_content.push('\n');
            }
        }
    }

    // Get file metadata for updated_at
    let metadata = fs::metadata(&policy_path)
        .map_err(|e| ApiError::Internal(format!("Failed to get policy metadata: {}", e)))?;

    let updated_at = metadata
        .modified()
        .ok()
        .and_then(|t| {
            let dt: chrono::DateTime<Utc> = t.into();
            Some(dt)
        })
        .unwrap_or(created_at);

    Ok(Json(PolicyResponse {
        id,
        name,
        description,
        rules: rules_content,
        enabled,
        created_at,
        updated_at,
    }))
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
    // Get policy directory
    let policy_dir = state
        .policy_dir
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Policy storage not configured".to_string()))?;

    // Load policy
    let policy_path = policy_dir.join(format!("{}.yaml", id));

    if !policy_path.exists() {
        return Err(ApiError::NotFound(format!("Policy {} not found", id)));
    }

    let policy = PolicyLoader::new(policy_dir.clone())
        .load(&policy_path)
        .map_err(|e| ApiError::Internal(format!("Failed to load policy: {}", e)))?;

    // Parse target (hostname:port)
    let parts: Vec<&str> = request.target.split(':').collect();
    let hostname = parts.first().ok_or_else(|| ApiError::BadRequest("Invalid target format. Expected hostname:port".to_string()))?;
    let port = parts.get(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(443);

    // Perform TLS scan - Create Args struct for Scanner
    let args = crate::Args {
        target: Some(format!("{}:{}", hostname, port)),
        port: Some(port),
        ..Default::default()
    };

    let mut scanner = Scanner::new(args)
        .map_err(|e| ApiError::Internal(format!("Failed to create scanner: {}", e)))?;

    let scan_results = scanner
        .run()
        .await
        .map_err(|e| ApiError::Internal(format!("Scan failed: {}", e)))?;

    // Evaluate policy against scan results
    let evaluator = PolicyEvaluator::new(policy.clone());
    let policy_result = evaluator
        .evaluate(&scan_results)
        .map_err(|e| ApiError::Internal(format!("Policy evaluation failed: {}", e)))?;

    // Convert violations to check results
    let checks: Vec<PolicyCheckResult> = policy_result
        .violations
        .iter()
        .map(|violation| PolicyCheckResult {
            check: violation.rule_name.clone(),
            passed: false,
            severity: format!("{:?}", violation.action).to_lowercase(),
            message: Some(violation.description.clone()),
            expected: violation.remediation.clone(),
            actual: violation.evidence.clone(),
        })
        .collect();

    // Generate scan ID for reference
    let scan_id = Uuid::new_v4().to_string();

    Ok(Json(PolicyEvaluationResponse {
        policy_id: id,
        policy_name: policy.name,
        target: request.target,
        compliant: !policy_result.has_violations(),
        checks,
        evaluated_at: Utc::now(),
        scan_id,
    }))
}

/// Sanitize filename to make it safe for filesystem
fn sanitize_filename(name: &str) -> String {
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
