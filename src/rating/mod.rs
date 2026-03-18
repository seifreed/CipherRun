// Rating module - SSL Labs rating and CVSS scoring

pub mod cvss;
pub mod grader;
pub mod scoring;

pub use cvss::{CvssCalculator, CvssScore, CvssSeverity, TlsVulnerabilityCvss};
pub use grader::Grade;
pub use scoring::{RatingCalculator, RatingResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grade_from_score_and_description() {
        let grade = Grade::from_score(97);
        assert_eq!(grade, Grade::APlus);
        assert!(grade.description().contains("Excellent"));
        assert_eq!(grade.to_string(), "A+");
    }

    #[test]
    fn test_cvss_severity_reexport() {
        assert_eq!(CvssSeverity::Critical.as_str(), "Critical");
    }
}
