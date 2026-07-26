use serde::{Deserialize, Serialize};

/// Schema validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl ValidationResult {
    pub fn success() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn failure(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }
}
