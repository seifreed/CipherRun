// SSL Labs Grading System - Convert scores to grades

use serde::{Deserialize, Serialize};

/// SSL Labs rating grade
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Grade {
    #[serde(rename = "A+")]
    APlus,
    A,
    #[serde(rename = "A-")]
    AMinus,
    B,
    C,
    D,
    E,
    F,
    T, // Trust issues (certificate)
    M, // Certificate name mismatch
}

impl Grade {
    /// Get color for grade
    pub fn color(&self) -> &'static str {
        match self {
            Grade::APlus | Grade::A => "green",
            Grade::AMinus | Grade::B => "blue",
            Grade::C => "yellow",
            Grade::D | Grade::E => "orange",
            Grade::F | Grade::T | Grade::M => "red",
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            Grade::APlus => "Excellent - Best practice security",
            Grade::A => "Excellent - Strong security",
            Grade::AMinus => "Excellent - Minor issues",
            Grade::B => "Good - Adequate security",
            Grade::C => "Fair - Mediocre security",
            Grade::D => "Poor - Weak security",
            Grade::E => "Poor - Very weak security",
            Grade::F => "Failing - Critical security issues",
            Grade::T => "Certificate not trusted",
            Grade::M => "Certificate name mismatch",
        }
    }

    /// Convert score to grade
    pub fn from_score(score: u8) -> Self {
        match score {
            95..=100 => Grade::APlus,
            85..=94 => Grade::A,
            80..=84 => Grade::AMinus,
            65..=79 => Grade::B,
            50..=64 => Grade::C,
            35..=49 => Grade::D,
            20..=34 => Grade::E,
            _ => Grade::F,
        }
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Grade::APlus => write!(f, "A+"),
            Grade::A => write!(f, "A"),
            Grade::AMinus => write!(f, "A-"),
            Grade::B => write!(f, "B"),
            Grade::C => write!(f, "C"),
            Grade::D => write!(f, "D"),
            Grade::E => write!(f, "E"),
            Grade::F => write!(f, "F"),
            Grade::T => write!(f, "T"),
            Grade::M => write!(f, "M"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_score() {
        assert_eq!(Grade::from_score(100), Grade::APlus);
        assert_eq!(Grade::from_score(90), Grade::A);
        assert_eq!(Grade::from_score(82), Grade::AMinus);
        assert_eq!(Grade::from_score(70), Grade::B);
        assert_eq!(Grade::from_score(55), Grade::C);
        assert_eq!(Grade::from_score(40), Grade::D);
        assert_eq!(Grade::from_score(25), Grade::E);
        assert_eq!(Grade::from_score(10), Grade::F);
    }

    #[test]
    fn test_grade_display() {
        assert_eq!(Grade::APlus.to_string(), "A+");
        assert_eq!(Grade::A.to_string(), "A");
        assert_eq!(Grade::AMinus.to_string(), "A-");
        assert_eq!(Grade::B.to_string(), "B");
    }

    #[test]
    fn test_grade_color() {
        assert_eq!(Grade::APlus.color(), "green");
        assert_eq!(Grade::B.color(), "blue");
        assert_eq!(Grade::C.color(), "yellow");
        assert_eq!(Grade::F.color(), "red");
    }
}
