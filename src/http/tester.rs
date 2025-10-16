// HTTP Security Headers Analyzer - Fetch and analyze HTTP headers

use super::headers::{HeaderIssue, SecurityHeaderChecker};
use crate::Result;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// HTTP header analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderAnalysisResult {
    pub headers: HashMap<String, String>,
    pub issues: Vec<HeaderIssue>,
    pub score: u8,
    pub grade: SecurityGrade,
}

/// Security grade
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityGrade {
    A,
    B,
    C,
    D,
    F,
}

/// HTTP security headers analyzer
pub struct HeaderAnalyzer {
    target: Target,
    timeout: Duration,
    custom_headers: Vec<(String, String)>,
    user_agent: String,
}

impl HeaderAnalyzer {
    /// Create new header analyzer
    pub fn new(target: Target) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(10),
            custom_headers: Vec::new(),
            user_agent: "CipherRun/0.1.0 (TLS/SSL Security Scanner)".to_string(),
        }
    }

    /// Create new header analyzer with custom headers
    pub fn with_custom_headers(target: Target, custom_headers: Vec<(String, String)>) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(10),
            custom_headers,
            user_agent: "CipherRun/0.1.0 (TLS/SSL Security Scanner)".to_string(),
        }
    }

    /// Set user agent
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Analyze HTTP security headers
    pub async fn analyze(&self) -> Result<HeaderAnalysisResult> {
        // Fetch headers via HTTPS
        let headers = self.fetch_headers().await?;

        // Check headers for issues
        let issues = SecurityHeaderChecker::check_all_headers(&headers);

        // Calculate score and grade
        let score = Self::calculate_score(&issues);
        let grade = Self::calculate_grade(score);

        Ok(HeaderAnalysisResult {
            headers,
            issues,
            score,
            grade,
        })
    }

    /// Fetch HTTP headers from target
    async fn fetch_headers(&self) -> Result<HashMap<String, String>> {
        let url = format!("https://{}:{}/", self.target.hostname, self.target.port);

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .danger_accept_invalid_certs(true) // Accept any cert since we're checking headers
            .user_agent(&self.user_agent)
            .build()?;

        let mut request = client.get(&url);

        // Add custom headers if specified
        for (name, value) in &self.custom_headers {
            request = request.header(name, value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch headers: {}", e))?;

        let mut headers = HashMap::new();
        for (name, value) in response.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string(), value_str.to_string());
            }
        }

        Ok(headers)
    }

    /// Calculate security score (0-100)
    fn calculate_score(issues: &[HeaderIssue]) -> u8 {
        use super::headers::IssueSeverity;

        let mut score: u8 = 100;

        for issue in issues {
            let deduction = match issue.severity {
                IssueSeverity::Critical => 20,
                IssueSeverity::High => 15,
                IssueSeverity::Medium => 10,
                IssueSeverity::Low => 5,
                IssueSeverity::Info => 0,
            };
            score = score.saturating_sub(deduction);
        }

        score
    }

    /// Calculate security grade from score
    fn calculate_grade(score: u8) -> SecurityGrade {
        match score {
            90..=100 => SecurityGrade::A,
            75..=89 => SecurityGrade::B,
            60..=74 => SecurityGrade::C,
            40..=59 => SecurityGrade::D,
            _ => SecurityGrade::F,
        }
    }
}

impl HeaderAnalysisResult {
    /// Get summary text
    pub fn summary(&self) -> String {
        format!(
            "Security Headers Grade: {:?} (Score: {}/100, {} issues)",
            self.grade,
            self.score,
            self.issues.len()
        )
    }

    /// Get critical and high severity issues
    pub fn critical_issues(&self) -> Vec<&HeaderIssue> {
        use super::headers::IssueSeverity;

        self.issues
            .iter()
            .filter(|i| matches!(i.severity, IssueSeverity::Critical | IssueSeverity::High))
            .collect()
    }

    /// Check if any critical or high issues exist
    pub fn has_serious_issues(&self) -> bool {
        !self.critical_issues().is_empty()
    }
}

impl SecurityGrade {
    /// Get color for grade
    pub fn color(&self) -> &'static str {
        match self {
            SecurityGrade::A => "green",
            SecurityGrade::B => "blue",
            SecurityGrade::C => "yellow",
            SecurityGrade::D => "orange",
            SecurityGrade::F => "red",
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            SecurityGrade::A => "Excellent security headers",
            SecurityGrade::B => "Good security headers",
            SecurityGrade::C => "Fair security headers",
            SecurityGrade::D => "Poor security headers",
            SecurityGrade::F => "Failing security headers",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::headers::IssueType;

    #[test]
    fn test_score_calculation() {
        let mut issues = Vec::new();

        // Add a high severity issue
        issues.push(HeaderIssue {
            header_name: "HSTS".to_string(),
            severity: crate::http::headers::IssueSeverity::High,
            issue_type: IssueType::Missing,
            description: "Missing HSTS".to_string(),
            recommendation: "Add HSTS".to_string(),
        });

        let score = HeaderAnalyzer::calculate_score(&issues);
        assert_eq!(score, 85); // 100 - 15
    }

    #[test]
    fn test_grade_calculation() {
        assert_eq!(HeaderAnalyzer::calculate_grade(95), SecurityGrade::A);
        assert_eq!(HeaderAnalyzer::calculate_grade(80), SecurityGrade::B);
        assert_eq!(HeaderAnalyzer::calculate_grade(65), SecurityGrade::C);
        assert_eq!(HeaderAnalyzer::calculate_grade(50), SecurityGrade::D);
        assert_eq!(HeaderAnalyzer::calculate_grade(30), SecurityGrade::F);
    }

    #[test]
    fn test_security_grade_color() {
        assert_eq!(SecurityGrade::A.color(), "green");
        assert_eq!(SecurityGrade::F.color(), "red");
    }
}
