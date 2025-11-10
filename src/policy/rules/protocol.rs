// Protocol policy rules

use crate::policy::violation::PolicyViolation;
use crate::policy::{PolicyAction, ProtocolPolicy};
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::Result;
use std::str::FromStr;

pub struct ProtocolRule<'a> {
    policy: &'a ProtocolPolicy,
    results: &'a [ProtocolTestResult],
}

impl<'a> ProtocolRule<'a> {
    pub fn new(policy: &'a ProtocolPolicy, results: &'a [ProtocolTestResult]) -> Self {
        Self { policy, results }
    }

    pub fn evaluate(&self, _target: &str) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        // Check for required protocols
        if let Some(ref required) = self.policy.required {
            for protocol_name in required {
                // Parse the protocol name to handle different string formats
                let protocol_match = Protocol::from_str(protocol_name).ok();

                let is_supported = self
                    .results
                    .iter()
                    .any(|r| {
                        if let Some(ref expected_protocol) = protocol_match {
                            r.protocol == *expected_protocol && r.supported
                        } else {
                            // Fallback to string comparison if parsing fails
                            r.protocol.to_string() == *protocol_name && r.supported
                        }
                    });

                if !is_supported {
                    violations.push(
                        PolicyViolation::new(
                            "protocols.required",
                            "Required Protocol Check",
                            self.policy.action,
                            format!("{} is required but not supported", protocol_name),
                        )
                        .with_evidence(format!(
                            "Server does not support required protocol: {}",
                            protocol_name
                        ))
                        .with_remediation(format!(
                            "Enable {} in server configuration",
                            protocol_name
                        )),
                    );
                }
            }
        }

        // Check for prohibited protocols
        if let Some(ref prohibited) = self.policy.prohibited {
            for protocol_name in prohibited {
                // Parse the protocol name to handle different string formats
                let protocol_match = Protocol::from_str(protocol_name).ok();

                let is_supported = self
                    .results
                    .iter()
                    .any(|r| {
                        if let Some(ref expected_protocol) = protocol_match {
                            r.protocol == *expected_protocol && r.supported
                        } else {
                            // Fallback to string comparison if parsing fails
                            r.protocol.to_string() == *protocol_name && r.supported
                        }
                    });

                if is_supported {
                    violations.push(
                        PolicyViolation::new(
                            "protocols.prohibited",
                            "Prohibited Protocol Check",
                            self.policy.action,
                            format!("{} is prohibited but enabled", protocol_name),
                        )
                        .with_evidence(format!(
                            "Server accepts {} connections",
                            protocol_name
                        ))
                        .with_remediation(format!(
                            "Disable {} in server configuration",
                            protocol_name
                        )),
                    );
                }
            }
        }

        Ok(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::Protocol;

    #[test]
    fn test_required_protocol_violation() {
        let policy = ProtocolPolicy {
            required: Some(vec!["TLSv1.3".to_string()]),
            prohibited: None,
            action: PolicyAction::Fail,
        };

        let results = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            ciphers_count: 0,
            preferred: false,
        }];

        let rule = ProtocolRule::new(&policy, &results);
        let violations = rule.evaluate("example.com:443").unwrap();

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.required");
    }

    #[test]
    fn test_prohibited_protocol_violation() {
        let policy = ProtocolPolicy {
            required: None,
            prohibited: Some(vec!["TLSv1.0".to_string()]),
            action: PolicyAction::Fail,
        };

        let results = vec![ProtocolTestResult {
            protocol: Protocol::TLS10,
            supported: true,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            ciphers_count: 0,
            preferred: false,
        }];

        let rule = ProtocolRule::new(&policy, &results);
        let violations = rule.evaluate("example.com:443").unwrap();

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }
}
