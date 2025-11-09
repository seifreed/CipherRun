// Policy rules module

pub mod certificate;
pub mod cipher;
pub mod protocol;
pub mod vulnerability;

use crate::policy::violation::PolicyViolation;
use crate::Result;

/// Trait for policy rules
pub trait PolicyRule {
    /// Evaluate the rule against scan results
    fn evaluate(&self, target: &str) -> Result<Vec<PolicyViolation>>;
}
