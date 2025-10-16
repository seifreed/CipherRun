// CVSS (Common Vulnerability Scoring System) v3.1 scoring
// For detailed vulnerability assessment
// Reference: https://www.first.org/cvss/v3.1/specification-document

use serde::{Deserialize, Serialize};

/// CVSS v3.1 Base Score Metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssScore {
    pub base_score: f64,
    pub temporal_score: Option<f64>,
    pub environmental_score: Option<f64>,
    pub base_metrics: BaseMetrics,
    pub severity: CvssSeverity,
    pub vector_string: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvssSeverity {
    None,     // 0.0
    Low,      // 0.1 - 3.9
    Medium,   // 4.0 - 6.9
    High,     // 7.0 - 8.9
    Critical, // 9.0 - 10.0
}

impl CvssSeverity {
    pub fn from_score(score: f64) -> Self {
        match score {
            0.0 => CvssSeverity::None,
            s if s < 4.0 => CvssSeverity::Low,
            s if s < 7.0 => CvssSeverity::Medium,
            s if s < 9.0 => CvssSeverity::High,
            _ => CvssSeverity::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CvssSeverity::None => "None",
            CvssSeverity::Low => "Low",
            CvssSeverity::Medium => "Medium",
            CvssSeverity::High => "High",
            CvssSeverity::Critical => "Critical",
        }
    }
}

/// CVSS Base Metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseMetrics {
    // Exploitability Metrics
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,

    // Impact Metrics
    pub confidentiality_impact: Impact,
    pub integrity_impact: Impact,
    pub availability_impact: Impact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVector {
    Network,  // N - 0.85
    Adjacent, // A - 0.62
    Local,    // L - 0.55
    Physical, // P - 0.2
}

impl AttackVector {
    pub fn score(&self) -> f64 {
        match self {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AttackVector::Network => "N",
            AttackVector::Adjacent => "A",
            AttackVector::Local => "L",
            AttackVector::Physical => "P",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackComplexity {
    Low,  // L - 0.77
    High, // H - 0.44
}

impl AttackComplexity {
    pub fn score(&self) -> f64 {
        match self {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AttackComplexity::Low => "L",
            AttackComplexity::High => "H",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    None, // N - 0.85 (unchanged) / 0.85 (changed)
    Low,  // L - 0.62 (unchanged) / 0.68 (changed)
    High, // H - 0.27 (unchanged) / 0.50 (changed)
}

impl PrivilegesRequired {
    pub fn score(&self, scope_changed: bool) -> f64 {
        match (self, scope_changed) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, false) => 0.62,
            (PrivilegesRequired::Low, true) => 0.68,
            (PrivilegesRequired::High, false) => 0.27,
            (PrivilegesRequired::High, true) => 0.50,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PrivilegesRequired::None => "N",
            PrivilegesRequired::Low => "L",
            PrivilegesRequired::High => "H",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserInteraction {
    None,     // N - 0.85
    Required, // R - 0.62
}

impl UserInteraction {
    pub fn score(&self) -> f64 {
        match self {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            UserInteraction::None => "N",
            UserInteraction::Required => "R",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Unchanged, // U
    Changed,   // C
}

impl Scope {
    pub fn is_changed(&self) -> bool {
        matches!(self, Scope::Changed)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Unchanged => "U",
            Scope::Changed => "C",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Impact {
    None, // N - 0.0
    Low,  // L - 0.22
    High, // H - 0.56
}

impl Impact {
    pub fn score(&self) -> f64 {
        match self {
            Impact::None => 0.0,
            Impact::Low => 0.22,
            Impact::High => 0.56,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Impact::None => "N",
            Impact::Low => "L",
            Impact::High => "H",
        }
    }
}

/// CVSS Calculator
pub struct CvssCalculator;

impl CvssCalculator {
    /// Calculate CVSS base score from metrics
    pub fn calculate_base_score(metrics: &BaseMetrics) -> f64 {
        // Impact Sub Score (ISS)
        let iss_base = 1.0
            - ((1.0 - metrics.confidentiality_impact.score())
                * (1.0 - metrics.integrity_impact.score())
                * (1.0 - metrics.availability_impact.score()));

        let impact = if metrics.scope.is_changed() {
            7.52 * (iss_base - 0.029) - 3.25 * (iss_base - 0.02).powi(15)
        } else {
            6.42 * iss_base
        };

        // If Impact <= 0, Base Score is 0
        if impact <= 0.0 {
            return 0.0;
        }

        // Exploitability Sub Score
        let exploitability = 8.22
            * metrics.attack_vector.score()
            * metrics.attack_complexity.score()
            * metrics
                .privileges_required
                .score(metrics.scope.is_changed())
            * metrics.user_interaction.score();

        // Base Score
        let base_score = if metrics.scope.is_changed() {
            (impact + exploitability).min(10.0)
        } else {
            ((impact + exploitability) * 1.08).min(10.0)
        };

        // Round up to 1 decimal place
        (base_score * 10.0).ceil() / 10.0
    }

    /// Generate CVSS vector string
    pub fn generate_vector_string(metrics: &BaseMetrics) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            metrics.attack_vector.as_str(),
            metrics.attack_complexity.as_str(),
            metrics.privileges_required.as_str(),
            metrics.user_interaction.as_str(),
            metrics.scope.as_str(),
            metrics.confidentiality_impact.as_str(),
            metrics.integrity_impact.as_str(),
            metrics.availability_impact.as_str()
        )
    }

    /// Calculate complete CVSS score
    pub fn calculate(metrics: BaseMetrics) -> CvssScore {
        let base_score = Self::calculate_base_score(&metrics);
        let severity = CvssSeverity::from_score(base_score);
        let vector_string = Self::generate_vector_string(&metrics);

        CvssScore {
            base_score,
            temporal_score: None,
            environmental_score: None,
            base_metrics: metrics,
            severity,
            vector_string,
        }
    }
}

/// Pre-defined CVSS scores for common TLS vulnerabilities
pub struct TlsVulnerabilityCvss;

impl TlsVulnerabilityCvss {
    /// CVSS for Heartbleed (CVE-2014-0160)
    pub fn heartbleed() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }

    /// CVSS for POODLE (CVE-2014-3566)
    pub fn poodle() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::Required,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::Low,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }

    /// CVSS for BEAST (CVE-2011-3389)
    pub fn beast() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::Required,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::Low,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }

    /// CVSS for CCS Injection (CVE-2014-0224)
    pub fn ccs_injection() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }

    /// CVSS for ROBOT (CVE-2017-17382)
    pub fn robot() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }

    /// CVSS for DROWN (CVE-2016-0800)
    pub fn drown() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }

    /// CVSS for FREAK (CVE-2015-0204)
    pub fn freak() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }

    /// CVSS for LOGJAM (CVE-2015-4000)
    pub fn logjam() -> CvssScore {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        CvssCalculator::calculate(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_severity_from_score() {
        assert_eq!(CvssSeverity::from_score(0.0), CvssSeverity::None);
        assert_eq!(CvssSeverity::from_score(3.9), CvssSeverity::Low);
        assert_eq!(CvssSeverity::from_score(5.0), CvssSeverity::Medium);
        assert_eq!(CvssSeverity::from_score(7.5), CvssSeverity::High);
        assert_eq!(CvssSeverity::from_score(9.5), CvssSeverity::Critical);
    }

    #[test]
    fn test_heartbleed_cvss() {
        let score = TlsVulnerabilityCvss::heartbleed();
        assert!(score.base_score >= 7.0); // Should be High or Critical
        assert!(score.vector_string.contains("CVSS:3.1"));
        assert!(score.vector_string.contains("AV:N")); // Network vector
        assert!(score.vector_string.contains("C:H")); // High confidentiality impact
    }

    #[test]
    fn test_cvss_vector_string() {
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::High,
        };

        let vector = CvssCalculator::generate_vector_string(&metrics);
        assert_eq!(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    }

    #[test]
    fn test_cvss_base_score_calculation() {
        // Maximum score (10.0)
        let metrics = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::High,
        };

        let score = CvssCalculator::calculate_base_score(&metrics);
        assert!(score >= 9.0); // Should be Critical

        // Zero score (no impact)
        let metrics_zero = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::None,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };

        let score_zero = CvssCalculator::calculate_base_score(&metrics_zero);
        assert_eq!(score_zero, 0.0);
    }
}
