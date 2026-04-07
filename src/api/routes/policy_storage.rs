use crate::api::{
    models::{error::ApiError, request::PolicyRequest},
    state::AppState,
};
use crate::security::sanitize_path;
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

/// Parsed policy metadata: (name, description, created_at, enabled, rules_content, updated_at)
pub(super) type PolicyMetadata = (
    String,
    Option<String>,
    chrono::DateTime<Utc>,
    bool,
    String,
    chrono::DateTime<Utc>,
);

pub(super) fn policy_dir_from_state(state: &AppState) -> Result<&PathBuf, ApiError> {
    state
        .policy_dir
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Policy storage not configured".to_string()))
}

pub(super) fn sanitized_policy_path(policy_dir: &Path, id: &str) -> Result<PathBuf, ApiError> {
    let filename = format!("{}.yaml", id);
    sanitize_path(&filename, policy_dir)
        .map_err(|e| ApiError::BadRequest(format!("Invalid policy ID: {}", e)))
}

pub(super) fn build_policy_content(request: &PolicyRequest, now: chrono::DateTime<Utc>) -> String {
    format!(
        "# Policy: {}\n# Description: {}\n# Created: {}\n# Enabled: {}\n\n{}",
        request.name,
        request
            .description
            .as_ref()
            .unwrap_or(&"No description".to_string()),
        now.to_rfc3339(),
        request.enabled,
        request.rules
    )
}

pub(super) fn parse_policy_file_content(
    id: String,
    content: &str,
) -> (String, Option<String>, chrono::DateTime<Utc>, bool, String) {
    let mut name = id;
    let mut description = None;
    let mut created_at = Utc::now();
    let mut enabled = true;
    let mut rules_content = String::new();
    let mut in_metadata = true;

    for line in content.lines() {
        if in_metadata && line.starts_with("# Policy: ") {
            let candidate = line.trim_start_matches("# Policy: ").to_string();
            if !candidate.is_empty() {
                name = candidate;
            }
        } else if in_metadata && line.starts_with("# Description: ") {
            let desc = line.trim_start_matches("# Description: ").to_string();
            if !desc.is_empty() && desc != "No description" {
                description = Some(desc);
            }
        } else if in_metadata && line.starts_with("# Created: ") {
            let date_str = line.trim_start_matches("# Created: ");
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date_str) {
                created_at = dt.with_timezone(&Utc);
            }
        } else if in_metadata && line.starts_with("# Enabled: ") {
            match line.trim_start_matches("# Enabled: ") {
                "true" => enabled = true,
                "false" => enabled = false,
                _ => {}
            }
        } else if !line.starts_with('#') {
            in_metadata = false;
            if !line.trim().is_empty() {
                rules_content.push_str(line);
                rules_content.push('\n');
            }
        }
    }

    (name, description, created_at, enabled, rules_content)
}

pub(super) fn read_policy_with_metadata(
    policy_path: &Path,
    fallback_id: String,
) -> Result<PolicyMetadata, ApiError> {
    let content = fs::read_to_string(policy_path)
        .map_err(|e| ApiError::Internal(format!("Failed to read policy file: {}", e)))?;
    let (name, description, created_at, enabled, rules_content) =
        parse_policy_file_content(fallback_id, &content);

    let metadata = fs::metadata(policy_path)
        .map_err(|e| ApiError::Internal(format!("Failed to get policy metadata: {}", e)))?;

    let updated_at = metadata
        .modified()
        .ok()
        .map(|t| {
            let dt: chrono::DateTime<Utc> = t.into();
            dt
        })
        .unwrap_or(created_at);

    Ok((
        name,
        description,
        created_at,
        enabled,
        rules_content,
        updated_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_file_content_uses_defaults_for_missing_metadata() {
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), "rules:\n  - check: true\n");

        assert_eq!(name, "fallback");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.contains("check: true"));
    }

    #[test]
    fn parse_policy_file_content_ignores_invalid_created_date() {
        let content = "# Policy: Policy\n# Created: not-a-date\n# Enabled: false\n\nrules: []\n";
        let before = Utc::now() - chrono::Duration::seconds(1);
        let (_name, _description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);
        let after = Utc::now() + chrono::Duration::seconds(1);

        assert!((before..=after).contains(&created_at));
        assert!(!enabled);
        assert_eq!(rules.trim(), "rules: []");
    }

    #[test]
    fn build_policy_content_uses_default_description() {
        let content = build_policy_content(
            &PolicyRequest {
                name: "Policy".to_string(),
                description: None,
                rules: "rules: []".to_string(),
                enabled: true,
            },
            Utc::now(),
        );

        assert!(content.contains("# Description: No description"));
        assert!(content.contains("rules: []"));
    }

    #[test]
    fn parse_policy_file_content_handles_partial_metadata_and_empty_rules() {
        let content = "# Policy: Partial\n# Enabled: false\n\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Partial");
        assert_eq!(description, None);
        assert!(!enabled);
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_policy_file_content_keeps_default_name_with_partial_invalid_metadata() {
        let content =
            "# Description: No description\n# Created: definitely-not-a-date\n\n# comment\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "fallback");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_policy_file_content_keeps_non_default_description_with_empty_rules() {
        let content = "# Policy: Partial\n# Description: Custom description\n# Enabled: true\n\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Partial");
        assert_eq!(description.as_deref(), Some("Custom description"));
        assert!(enabled);
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_policy_file_content_preserves_non_metadata_rule_lines() {
        let content =
            "# Policy: Example\n# Enabled: true\n\nrules:\n  - type: allow\n# trailing comment\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("rules:"));
        assert!(rules.contains("- type: allow"));
    }

    #[test]
    fn parse_policy_file_content_ignores_unknown_metadata_comments_before_rules() {
        let content =
            "# Policy: Example\n# Unknown: value\n# Another: value\n\nrules:\n  - enabled: true\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Example");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.contains("enabled: true"));
    }

    #[test]
    fn parse_policy_file_content_ignores_blank_lines_before_rules() {
        let content = "# Policy: Example\n# Enabled: false\n\n\nrules:\n  - severity: high\n";
        let (name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Example");
        assert!(!enabled);
        assert!(rules.contains("severity: high"));
    }

    #[test]
    fn parse_policy_file_content_treats_indented_comments_inside_rules_as_content_boundary() {
        let content = "# Policy: Example\n# Enabled: true\n\nrules:\n  - severity: high\n  # inline comment\n  - enabled: true\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("severity: high"));
        assert!(rules.contains("enabled: true"));
    }

    #[test]
    fn parse_policy_file_content_keeps_comments_after_rules_out_of_results() {
        let content = "# Policy: Example\n# Enabled: true\n\nrules:\n  - severity: high\n# post rules comment\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("severity: high"));
        assert!(!rules.contains("post rules comment"));
    }

    #[test]
    fn parse_policy_file_content_ignores_metadata_comments_between_blank_lines() {
        let content = "# Policy: Example\n\n# Unknown: value\n\nrules:\n  - action: allow\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Example");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_discards_comment_only_tail_after_rules() {
        let content = "# Policy: Example\n# Enabled: true\n\nrules:\n  - action: allow\n\n# trailing\n# comment\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("action: allow"));
        assert!(!rules.contains("trailing"));
    }

    #[test]
    fn parse_policy_file_content_last_metadata_wins_for_repeated_fields() {
        let content = "# Policy: First\n# Policy: Second\n# Enabled: false\n# Enabled: true\n\nrules:\n  - action: allow\n";
        let (name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Second");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_last_description_wins_when_repeated() {
        let content = "# Policy: Example\n# Description: First\n# Description: Second\n\nrules:\n  - action: deny\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Second"));
        assert!(enabled);
        assert!(rules.contains("action: deny"));
    }

    #[test]
    fn parse_policy_file_content_last_created_timestamp_wins_when_repeated() {
        let content = "# Policy: Example\n# Created: 2025-01-01T00:00:00Z\n# Created: 2025-02-02T00:00:00Z\n\nrules:\n  - action: allow\n";
        let (_name, _description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(created_at.to_rfc3339(), "2025-02-02T00:00:00+00:00");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_non_empty_policy_name_when_blank_value_follows() {
        let content = "# Policy: Example\n# Policy: \n\nrules:\n  - action: allow\n";
        let (name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Example");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_last_enabled_flag_wins_when_repeated() {
        let content =
            "# Policy: Example\n# Enabled: true\n# Enabled: false\n\nrules:\n  - action: audit\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(!enabled);
        assert!(rules.contains("action: audit"));
    }

    #[test]
    fn parse_policy_file_content_default_description_can_be_overridden_later() {
        let content = "# Policy: Example\n# Description: No description\n# Description: Real description\n\nrules:\n  - action: allow\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Real description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_created_timestamp_when_invalid_value_follows() {
        let content = "# Policy: Example\n# Created: 2025-01-01T00:00:00Z\n# Created: not-a-date\n\nrules:\n  - action: allow\n";
        let (_name, _description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(created_at.to_rfc3339(), "2025-01-01T00:00:00+00:00");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_ignores_partial_corrupt_metadata_before_rules() {
        let content = "# Policy:\n# Description:\n# Enabled: maybe\n# Created: still-not-a-date\n\nrules:\n  - enforce: true\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "fallback");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.contains("enforce: true"));
    }

    #[test]
    fn parse_policy_file_content_ignores_empty_description_even_when_repeated() {
        let content = "# Policy: Example\n# Description: Useful description\n# Description: \n\nrules:\n  - action: allow\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Useful description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_enabled_flag_when_invalid_value_follows() {
        let content =
            "# Policy: Example\n# Enabled: false\n# Enabled: maybe\n\nrules:\n  - action: deny\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(!enabled);
        assert!(rules.contains("action: deny"));
    }

    #[test]
    fn parse_policy_file_content_last_valid_enabled_flag_wins_after_invalid_value() {
        let content =
            "# Policy: Example\n# Enabled: maybe\n# Enabled: false\n\nrules:\n  - action: allow\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(!enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_last_valid_created_timestamp_wins_after_invalid_value() {
        let content = "# Policy: Example\n# Created: invalid-date\n# Created: 2025-03-01T00:00:00Z\n\nrules:\n  - action: audit\n";
        let (_name, _description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(created_at.to_rfc3339(), "2025-03-01T00:00:00+00:00");
        assert!(enabled);
        assert!(rules.contains("action: audit"));
    }

    #[test]
    fn parse_policy_file_content_last_valid_enabled_flag_wins_with_invalid_between_values() {
        let content = "# Policy: Example\n# Enabled: false\n# Enabled: maybe\n# Enabled: true\n\nrules:\n  - action: allow\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_non_default_description_when_empty_value_follows() {
        let content = "# Policy: Example\n# Description: Useful description\n# Description: \n# Description: No description\n\nrules:\n  - action: allow\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Useful description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_non_empty_policy_name_when_invalid_metadata_follows() {
        let content =
            "# Policy: Useful\n# Policy: \n# Enabled: maybe\n\nrules:\n  - action: audit\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Useful");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.contains("action: audit"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_created_timestamp_with_blank_following_value() {
        let content = "# Policy: Example\n# Created: 2025-04-01T00:00:00Z\n# Created: \n\nrules:\n  - action: allow\n";
        let (_name, _description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(created_at.to_rfc3339(), "2025-04-01T00:00:00+00:00");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_last_non_empty_policy_name_wins_after_blank_value() {
        let content = "# Policy: \n# Policy: Useful\n\nrules:\n  - action: allow\n";
        let (name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Useful");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_non_default_description_when_blank_values_repeat() {
        let content = "# Policy: Example\n# Description: Useful description\n# Description: \n# Description: \n\nrules:\n  - action: allow\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Useful description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_name_and_description_with_blank_repetitions() {
        let content = "# Policy: Useful\n# Policy: \n# Description: First description\n# Description: \n# Policy: Final\n# Description: Final description\n# Description: \n\nrules:\n  - action: allow\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Final");
        assert_eq!(description.as_deref(), Some("Final description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_metadata_when_blank_and_invalid_values_follow() {
        let content = "# Policy: Useful\n# Description: Useful description\n# Enabled: false\n# Created: 2025-05-01T00:00:00Z\n# Policy: \n# Description: \n# Enabled: maybe\n# Created: \n\nrules:\n  - action: audit\n";
        let (name, description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Useful");
        assert_eq!(description.as_deref(), Some("Useful description"));
        assert!(!enabled);
        assert_eq!(created_at.to_rfc3339(), "2025-05-01T00:00:00+00:00");
        assert!(rules.contains("action: audit"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_enabled_and_created_with_repeated_invalid_tail() {
        let content = "# Policy: Useful\n# Enabled: true\n# Created: 2025-06-01T00:00:00Z\n# Enabled: maybe\n# Created: invalid\n# Enabled: \n# Created: \n\nrules:\n  - action: allow\n";
        let (_name, _description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert_eq!(created_at.to_rfc3339(), "2025-06-01T00:00:00+00:00");
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_name_when_blank_and_default_metadata_follow() {
        let content = "# Policy: Useful\n# Description: Useful description\n# Policy: \n# Description: No description\n# Description: \n\nrules:\n  - action: allow\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Useful");
        assert_eq!(description.as_deref(), Some("Useful description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_description_when_default_and_blank_repeat() {
        let content = "# Policy: Useful\n# Description: Useful description\n# Description: No description\n# Description: \n# Description: No description\n\nrules:\n  - action: allow\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Useful description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_last_valid_description_wins_after_default_and_blank_noise() {
        let content = "# Policy: Useful\n# Description: No description\n# Description: \n# Description: Final description\n# Description: No description\n# Description: \n\nrules:\n  - action: allow\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Final description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_name_when_default_and_blank_noise_follow() {
        let content = "# Policy: Useful\n# Policy: \n# Policy: Useful Final\n# Policy: \n# Description: No description\n\nrules:\n  - action: allow\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Useful Final");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_name_after_default_description_noise() {
        let content = "# Policy: Useful\n# Description: No description\n# Policy: Final\n# Description: \n# Description: No description\n\nrules:\n  - action: allow\n";
        let (name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Final");
        assert_eq!(description, None);
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_enabled_after_blank_and_invalid_noise() {
        let content = "# Policy: Useful\n# Enabled: false\n# Enabled: \n# Enabled: maybe\n# Enabled: true\n# Enabled: \n\nrules:\n  - action: allow\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_created_after_blank_and_invalid_noise() {
        let content = "# Policy: Useful\n# Created: 2025-07-01T00:00:00Z\n# Created: \n# Created: invalid\n# Created: 2025-08-01T00:00:00Z\n# Created: \n\nrules:\n  - action: allow\n";
        let (_name, _description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(created_at.to_rfc3339(), "2025-08-01T00:00:00+00:00");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_metadata_after_default_noise() {
        let content = "# Policy: Strong TLS\n# Description: Enforce hardened baseline\n# Enabled: true\n# Created: 2025-01-01T00:00:00Z\n# Policy: \n# Description: No description\n# Enabled: \n# Enabled: maybe\n# Created: \n# Created: invalid\n\nrules:\n  - action: allow\n";
        let (name, description, created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Strong TLS");
        assert_eq!(description.as_deref(), Some("Enforce hardened baseline"));
        assert_eq!(created_at.to_rfc3339(), "2025-01-01T00:00:00+00:00");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_enabled_when_invalid_tail_repeats() {
        let content = "# Policy: Useful\n# Enabled: false\n# Enabled: true\n# Enabled: maybe\n# Enabled: \n# Enabled: invalid\n\nrules:\n  - action: allow\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_policy_after_blank_and_default_tail() {
        let content = "# Policy: Initial\n# Policy: Final Policy\n# Policy: \n# Description: No description\n# Policy: \n\nrules:\n  - action: allow\n";
        let (name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(name, "Final Policy");
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_description_after_blank_and_default_tail() {
        let content = "# Description: Initial description\n# Description: Final description\n# Description: \n# Description: No description\n\nrules:\n  - action: allow\n";
        let (_name, description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert_eq!(description.as_deref(), Some("Final description"));
        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn parse_policy_file_content_keeps_last_valid_enabled_after_false_tail_noise() {
        let content = "# Enabled: true\n# Enabled: false\n# Enabled: \n# Enabled: invalid\n# Enabled: true\n\nrules:\n  - action: allow\n";
        let (_name, _description, _created_at, enabled, rules) =
            parse_policy_file_content("fallback".to_string(), content);

        assert!(enabled);
        assert!(rules.contains("action: allow"));
    }

    #[test]
    fn sanitized_policy_path_rejects_traversal() {
        let base = std::env::temp_dir();
        let err = sanitized_policy_path(&base, "../escape").expect_err("path should be rejected");
        assert!(err.to_string().contains("Invalid policy ID"));
    }

    #[test]
    fn read_policy_with_metadata_uses_created_at_when_modified_unavailable() {
        let temp_dir =
            std::env::temp_dir().join(format!("policy-storage-test-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).expect("create dir");
        let policy_path = temp_dir.join("policy.yaml");
        let content =
            "# Policy: Policy\n# Created: 2024-01-02T03:04:05Z\n# Enabled: true\n\nrules: []\n";
        std::fs::write(&policy_path, content).expect("write policy");

        let (name, description, created_at, enabled, rules, updated_at) =
            read_policy_with_metadata(&policy_path, "fallback".to_string()).expect("read policy");

        assert_eq!(name, "Policy");
        assert_eq!(description, None);
        assert!(enabled);
        assert_eq!(rules.trim(), "rules: []");
        assert!(updated_at >= created_at);

        let _ = std::fs::remove_file(policy_path);
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
