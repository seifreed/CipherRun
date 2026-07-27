// Protocol policy rules

use crate::Result;
use crate::policy::ProtocolPolicy;
use crate::policy::violation::PolicyViolation;
use crate::protocols::{Protocol, ProtocolTestResult};
use std::str::FromStr;

pub struct ProtocolRule<'a> {
    policy: &'a ProtocolPolicy,
    results: &'a [ProtocolTestResult],
    any_supported_protocols: &'a [Protocol],
}

impl<'a> ProtocolRule<'a> {
    pub fn new(
        policy: &'a ProtocolPolicy,
        results: &'a [ProtocolTestResult],
        any_supported_protocols: &'a [Protocol],
    ) -> Self {
        Self {
            policy,
            results,
            any_supported_protocols,
        }
    }

    pub fn evaluate(&self, _target: &str) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        // Check for required protocols
        if let Some(ref required) = self.policy.required {
            for protocol_name in required {
                // Parse the protocol name to handle different string formats
                let protocol_match = Self::parse_policy_protocol("required", protocol_name)?;

                let is_supported =
                    self.protocol_supported_by_any_result(protocol_name, Some(&protocol_match));

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
                let protocol_match = Self::parse_policy_protocol("prohibited", protocol_name)?;

                let is_supported =
                    self.protocol_supported_on_any_backend(protocol_name, Some(&protocol_match));

                if is_supported {
                    violations.push(
                        PolicyViolation::new(
                            "protocols.prohibited",
                            "Prohibited Protocol Check",
                            self.policy.action,
                            format!("{} is prohibited but enabled", protocol_name),
                        )
                        .with_evidence(format!("Server accepts {} connections", protocol_name))
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

    fn parse_policy_protocol(field: &str, protocol_name: &str) -> Result<Protocol> {
        Protocol::from_str(protocol_name).map_err(|error| crate::TlsError::ConfigError {
            message: format!("Invalid protocol in {} list: {}", field, error),
        })
    }

    /// Check if a protocol is supported by checking if ANY result matches
    /// This is used for REQUIRED protocols - a protocol is "supported" if at least
    /// one result shows it working.
    fn protocol_supported_by_any_result(
        &self,
        protocol_name: &str,
        protocol_match: Option<&Protocol>,
    ) -> bool {
        self.results.iter().any(|r| {
            if let Some(expected_protocol) = protocol_match {
                r.protocol == *expected_protocol && r.supported
            } else {
                r.protocol.to_string() == protocol_name && r.supported
            }
        })
    }

    fn protocol_supported_on_any_backend(
        &self,
        protocol_name: &str,
        protocol_match: Option<&Protocol>,
    ) -> bool {
        if self.protocol_supported_by_any_result(protocol_name, protocol_match) {
            return true;
        }

        if let Some(expected_protocol) = protocol_match {
            self.any_supported_protocols
                .iter()
                .any(|protocol| protocol == expected_protocol)
        } else {
            self.any_supported_protocols
                .iter()
                .any(|protocol| protocol.to_string() == protocol_name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyAction;
    use crate::protocols::Protocol;

    fn protocol_result(protocol: Protocol, supported: bool) -> ProtocolTestResult {
        ProtocolTestResult {
            protocol,
            supported,
            inconclusive: false,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            ciphers_count: 0,
            preferred: false,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }
    }

    fn base_policy() -> ProtocolPolicy {
        ProtocolPolicy {
            required: None,
            prohibited: None,
            action: PolicyAction::Fail,
        }
    }

    fn required(protocol: &str) -> ProtocolPolicy {
        ProtocolPolicy {
            required: Some(vec![protocol.to_string()]),
            ..base_policy()
        }
    }

    fn prohibited(protocol: &str) -> ProtocolPolicy {
        ProtocolPolicy {
            prohibited: Some(vec![protocol.to_string()]),
            ..base_policy()
        }
    }

    fn violations(
        policy: &ProtocolPolicy,
        results: &[ProtocolTestResult],
        any_supported_protocols: &[Protocol],
    ) -> Vec<PolicyViolation> {
        ProtocolRule::new(policy, results, any_supported_protocols)
            .evaluate("example.com:443")
            .expect("test assertion should succeed")
    }

    #[test]
    fn test_protocol_rejects_invalid_names() {
        for (case, policy, expected) in [
            (
                "required",
                required("TLSv9.9"),
                "Invalid protocol in required list",
            ),
            (
                "prohibited",
                prohibited("TLSv9.9"),
                "Invalid protocol in prohibited list",
            ),
        ] {
            let rule = ProtocolRule::new(&policy, &[], &[]);
            let error = rule.evaluate("example.com:443").expect_err(case);

            assert!(error.to_string().contains(expected), "{case}");
        }
    }

    #[test]
    fn test_required_protocol_violation() {
        let policy = required("TLSv1.3");
        let results = vec![protocol_result(Protocol::TLS12, true)];
        let violations = violations(&policy, &results, &[Protocol::TLS12]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.required");
    }

    #[test]
    fn test_prohibited_protocol_violation() {
        let policy = prohibited("TLSv1.0");
        let results = vec![protocol_result(Protocol::TLS10, true)];
        let violations = violations(&policy, &results, &[Protocol::TLS10]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }

    #[test]
    fn test_prohibited_protocol_uses_direct_results_when_any_supported_list_is_empty() {
        let policy = prohibited("TLSv1.0");
        let results = vec![protocol_result(Protocol::TLS10, true)];
        let violations = violations(&policy, &results, &[]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }

    #[test]
    fn test_required_protocol_satisfied() {
        let policy = required("TLS 1.2");
        let results = vec![protocol_result(Protocol::TLS12, true)];
        let violations = violations(&policy, &results, &[Protocol::TLS12]);

        assert!(violations.is_empty());
    }

    #[test]
    fn test_prohibited_protocol_with_spaces() {
        let policy = prohibited("TLS 1.2");
        let results = vec![protocol_result(Protocol::TLS12, true)];
        let violations = violations(&policy, &results, &[Protocol::TLS12]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }

    #[test]
    fn test_required_protocol_with_underscore_alias_is_satisfied() {
        let policy = required("tls1_2");
        let results = vec![protocol_result(Protocol::TLS12, true)];
        let violations = violations(&policy, &results, &[Protocol::TLS12]);

        assert!(violations.is_empty());
    }

    #[test]
    fn test_prohibited_protocol_with_underscore_alias_is_detected() {
        let policy = prohibited("tls1_2");
        let results = vec![protocol_result(Protocol::TLS12, true)];
        let violations = violations(&policy, &results, &[Protocol::TLS12]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }

    #[test]
    fn test_prohibited_protocol_not_supported_no_violation() {
        let policy = prohibited("TLSv1.3");
        let results = vec![protocol_result(Protocol::TLS13, false)];
        let violations = violations(&policy, &results, &[]);

        assert!(violations.is_empty());
    }

    #[test]
    fn test_prohibited_protocol_violation_when_supported_on_subset_of_backends() {
        let policy = prohibited("TLSv1.0");
        let results = vec![protocol_result(Protocol::TLS10, false)];
        let violations = violations(&policy, &results, &[Protocol::TLS10]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }
}
