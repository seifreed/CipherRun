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
                let protocol_match = Protocol::from_str(protocol_name).ok();

                let is_supported =
                    self.protocol_supported_by_any_result(protocol_name, protocol_match.as_ref());

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

                let is_supported =
                    self.protocol_supported_on_any_backend(protocol_name, protocol_match.as_ref());

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
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let rule = ProtocolRule::new(&policy, &results, &[Protocol::TLS12]);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

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
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let rule = ProtocolRule::new(&policy, &results, &[Protocol::TLS10]);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }

    #[test]
    fn test_required_protocol_satisfied() {
        let policy = ProtocolPolicy {
            required: Some(vec!["TLS 1.2".to_string()]),
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
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let rule = ProtocolRule::new(&policy, &results, &[Protocol::TLS12]);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

        assert!(violations.is_empty());
    }

    #[test]
    fn test_prohibited_protocol_with_spaces() {
        let policy = ProtocolPolicy {
            required: None,
            prohibited: Some(vec!["TLS 1.2".to_string()]),
            action: PolicyAction::Fail,
        };

        let results = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            ciphers_count: 0,
            preferred: false,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let rule = ProtocolRule::new(&policy, &results, &[Protocol::TLS12]);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }

    #[test]
    fn test_prohibited_protocol_not_supported_no_violation() {
        let policy = ProtocolPolicy {
            required: None,
            prohibited: Some(vec!["TLSv1.3".to_string()]),
            action: PolicyAction::Fail,
        };

        let results = vec![ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: false,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            ciphers_count: 0,
            preferred: false,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let rule = ProtocolRule::new(&policy, &results, &[]);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

        assert!(violations.is_empty());
    }

    #[test]
    fn test_prohibited_protocol_violation_when_supported_on_subset_of_backends() {
        let policy = ProtocolPolicy {
            required: None,
            prohibited: Some(vec!["TLSv1.0".to_string()]),
            action: PolicyAction::Fail,
        };

        let results = vec![ProtocolTestResult {
            protocol: Protocol::TLS10,
            supported: false,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            ciphers_count: 0,
            preferred: false,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let rule = ProtocolRule::new(&policy, &results, &[Protocol::TLS10]);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "protocols.prohibited");
    }
}
