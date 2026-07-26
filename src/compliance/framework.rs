// Framework definitions and structures

use crate::compliance::{Rule, Severity};
use serde::{Deserialize, Serialize};

/// A compliance framework (e.g., PCI-DSS, NIST)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    /// Unique identifier (e.g., "pci-dss-v4")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Version number
    pub version: String,
    /// Description of the framework
    pub description: String,
    /// Organization that publishes this framework
    pub organization: String,
    /// Effective date of this version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_date: Option<String>,
    /// List of requirements in this framework
    pub requirements: Vec<Requirement>,
}

/// A single requirement within a compliance framework
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    /// Requirement identifier (e.g., "PCI-4.2.1")
    pub id: String,
    /// Short name of the requirement
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Category (e.g., "Protocol Security")
    pub category: String,
    /// Severity if this requirement is not met
    pub severity: Severity,
    /// Remediation advice
    #[serde(default)]
    pub remediation: String,
    /// Rules that define how to check this requirement
    pub rules: Vec<Rule>,
}

impl ComplianceFramework {
    /// Get a requirement by ID
    pub fn get_requirement(&self, id: &str) -> Option<&Requirement> {
        self.requirements.iter().find(|r| r.id == id)
    }

    /// Get all requirements in a specific category
    pub fn requirements_by_category(&self, category: &str) -> Vec<&Requirement> {
        self.requirements
            .iter()
            .filter(|r| r.category == category)
            .collect()
    }

    /// Get all requirements with a specific severity
    pub fn requirements_by_severity(&self, severity: Severity) -> Vec<&Requirement> {
        self.requirements
            .iter()
            .filter(|r| r.severity == severity)
            .collect()
    }

    /// Get all unique categories in this framework
    pub fn categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .requirements
            .iter()
            .map(|r| r.category.clone())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirement(id: &str, name: &str, category: &str, severity: Severity) -> Requirement {
        Requirement {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            category: category.to_string(),
            severity,
            remediation: String::new(),
            rules: vec![],
        }
    }

    fn framework(requirements: Vec<Requirement>) -> ComplianceFramework {
        ComplianceFramework {
            id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0".to_string(),
            description: "Test framework".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements,
        }
    }

    #[test]
    fn test_framework_get_requirement() {
        let framework = framework(vec![requirement(
            "TEST-1",
            "Test Requirement",
            "Security",
            Severity::High,
        )]);

        assert!(framework.get_requirement("TEST-1").is_some());
        assert!(framework.get_requirement("TEST-2").is_none());
    }

    #[test]
    fn test_framework_categories() {
        let framework = framework(vec![
            requirement("TEST-1", "Test 1", "Protocol Security", Severity::High),
            requirement("TEST-2", "Test 2", "Cipher Security", Severity::High),
            requirement("TEST-3", "Test 3", "Protocol Security", Severity::Medium),
        ]);

        let categories = framework.categories();
        assert_eq!(categories.len(), 2);
        assert!(categories.contains(&"Protocol Security".to_string()));
        assert!(categories.contains(&"Cipher Security".to_string()));
    }

    #[test]
    fn test_requirements_by_category_and_severity() {
        let framework = framework(vec![
            requirement("REQ-1", "Req 1", "Protocols", Severity::High),
            requirement("REQ-2", "Req 2", "Ciphers", Severity::Medium),
        ]);

        let protocols = framework.requirements_by_category("Protocols");
        assert_eq!(protocols.len(), 1);
        assert_eq!(protocols[0].id, "REQ-1");

        let high = framework.requirements_by_severity(Severity::High);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].id, "REQ-1");
    }
}
