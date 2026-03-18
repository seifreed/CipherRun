use crate::api::models::{request::PolicyRequest, response::PolicyResponse};
use chrono::{DateTime, Utc};

pub fn present_created_policy(
    policy_id: String,
    request: PolicyRequest,
    timestamp: DateTime<Utc>,
) -> PolicyResponse {
    PolicyResponse {
        id: policy_id,
        name: request.name,
        description: request.description,
        rules: request.rules,
        enabled: request.enabled,
        created_at: timestamp,
        updated_at: timestamp,
    }
}

pub fn present_loaded_policy(
    id: String,
    name: String,
    description: Option<String>,
    rules: String,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> PolicyResponse {
    PolicyResponse {
        id,
        name,
        description,
        rules,
        enabled,
        created_at,
        updated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_policy_response_from_request() {
        let now = Utc::now();
        let response = present_created_policy(
            "policy-id".to_string(),
            PolicyRequest {
                name: "Policy".to_string(),
                description: Some("Desc".to_string()),
                rules: "rules: []".to_string(),
                enabled: true,
            },
            now,
        );

        assert_eq!(response.id, "policy-id");
        assert_eq!(response.name, "Policy");
        assert_eq!(response.created_at, now);
    }

    #[test]
    fn creates_loaded_policy_response() {
        let created_at = Utc::now() - chrono::Duration::days(1);
        let updated_at = Utc::now();
        let response = present_loaded_policy(
            "policy-id".to_string(),
            "Loaded Policy".to_string(),
            None,
            "rules: []".to_string(),
            false,
            created_at,
            updated_at,
        );

        assert_eq!(response.id, "policy-id");
        assert_eq!(response.name, "Loaded Policy");
        assert!(!response.enabled);
        assert_eq!(response.description, None);
        assert_eq!(response.created_at, created_at);
        assert_eq!(response.updated_at, updated_at);
    }
}
