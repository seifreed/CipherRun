// JSON Schema for CipherRun output
// Validates and provides schema for structured output

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// JSON Schema for CipherRun scan results
pub struct CipherRunSchema;

impl CipherRunSchema {
    /// Get the complete JSON schema for scan results
    pub fn get_schema() -> Value {
        json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "CipherRun Scan Results",
            "description": "Complete TLS/SSL security scan results from CipherRun",
            "type": "object",
            "required": ["target", "scan_time_ms", "protocols", "ciphers", "vulnerabilities"],
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target scanned"
                },
                "scan_time_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total scan time in milliseconds"
                },
                "protocols": {
                    "type": "array",
                    "description": "Supported TLS/SSL protocols",
                    "items": {
                        "type": "object",
                        "required": ["protocol", "supported", "inconclusive", "preferred", "ciphers_count"],
                        "properties": {
                            "protocol": {
                                "type": "string",
                                "enum": ["SSLv2", "SSLv3", "TLS10", "TLS11", "TLS12", "TLS13", "QUIC"]
                            },
                            "supported": { "type": "boolean" },
                            "inconclusive": { "type": "boolean" },
                            "preferred": { "type": "boolean" },
                            "ciphers_count": { "type": "integer", "minimum": 0 },
                            "handshake_time_ms": { "type": ["integer", "null"], "minimum": 0 },
                            "heartbeat_enabled": { "type": ["boolean", "null"] },
                            "session_resumption_caching": { "type": ["boolean", "null"] },
                            "session_resumption_tickets": { "type": ["boolean", "null"] },
                            "secure_renegotiation": { "type": ["boolean", "null"] }
                        }
                    }
                },
                "ciphers": {
                    "type": "object",
                    "description": "Cipher suites per protocol",
                    "patternProperties": {
                        "^.*$": {
                            "type": "object",
                            "properties": {
                                "supported_ciphers": {
                                    "type": "array",
                                    "items": { "type": "string" }
                                },
                                "counts": {
                                    "type": "object",
                                    "properties": {
                                        "total": { "type": "integer" },
                                        "forward_secrecy": { "type": "integer" },
                                        "aead": { "type": "integer" },
                                        "high_strength": { "type": "integer" },
                                        "medium_strength": { "type": "integer" },
                                        "low_strength": { "type": "integer" },
                                        "export_ciphers": { "type": "integer" },
                                        "null_ciphers": { "type": "integer" }
                                    }
                                }
                            }
                        }
                    }
                },
                "certificate_chain": {
                    "type": ["object", "null"],
                    "description": "Certificate chain information",
                    "properties": {
                        "chain": {
                            "type": "object",
                            "properties": {
                                "certificates": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "subject": { "type": "string" },
                                            "issuer": { "type": "string" },
                                            "serial_number": { "type": "string" },
                                            "not_before": { "type": "string" },
                                            "not_after": { "type": "string" },
                                            "expiry_countdown": { "type": ["string", "null"] },
                                            "signature_algorithm": { "type": "string" },
                                            "public_key_algorithm": { "type": "string" },
                                            "public_key_size": { "type": ["integer", "null"], "minimum": 0 },
                                            "rsa_exponent": { "type": ["string", "null"] },
                                            "san": { "type": "array", "items": { "type": "string" } },
                                            "is_ca": { "type": "boolean" },
                                            "key_usage": { "type": "array", "items": { "type": "string" } },
                                            "extended_key_usage": { "type": "array", "items": { "type": "string" } },
                                            "extended_validation": { "type": "boolean" },
                                            "ev_oids": { "type": "array", "items": { "type": "string" } },
                                            "pin_sha256": { "type": ["string", "null"] },
                                            "fingerprint_sha256": { "type": ["string", "null"] },
                                            "debian_weak_key": { "type": ["boolean", "null"] },
                                            "aia_url": { "type": ["string", "null"] },
                                            "certificate_transparency": { "type": ["string", "null"] }
                                        }
                                    }
                                },
                                "chain_length": { "type": "integer", "minimum": 0 },
                                "chain_size_bytes": { "type": "integer", "minimum": 0 }
                            }
                        },
                        "validation": {
                            "type": "object",
                            "properties": {
                                "valid": { "type": "boolean" },
                                "not_expired": { "type": "boolean" },
                                "hostname_match": { "type": "boolean" },
                                "trust_chain_valid": { "type": "boolean" },
                                "signature_valid": { "type": "boolean" },
                                "trusted_ca": { "type": ["object", "null"] },
                                "platform_trust": { "type": ["object", "null"] }
                            }
                        },
                        "revocation": { "type": ["object", "null"] }
                    }
                },
                "vulnerabilities": {
                    "type": "array",
                    "description": "Detected vulnerabilities",
                    "items": {
                        "type": "object",
                        "required": ["vuln_type", "vulnerable", "inconclusive", "details", "severity"],
                        "properties": {
                            "vuln_type": { "type": "string" },
                            "vulnerable": { "type": "boolean" },
                            "inconclusive": { "type": "boolean" },
                            "details": { "type": "string" },
                            "severity": {
                                "type": "string",
                                "enum": ["Critical", "High", "Medium", "Low", "Info"]
                            },
                            "description": { "type": "string" },
                            "cve": { "type": ["string", "null"] },
                            "cwe": { "type": ["string", "null"] },
                            "cvss_score": { "type": "number", "minimum": 0.0, "maximum": 10.0 }
                        }
                    }
                },
                "rating": {
                    "type": ["object", "null"],
                    "description": "SSL Labs style rating",
                    "properties": {
                        "ssl_rating": {
                            "type": ["object", "null"],
                            "properties": {
                                "grade": {
                                    "type": "string",
                                    "enum": ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M", "Unverified"]
                                },
                                "score": { "type": "integer", "minimum": 0, "maximum": 100 },
                                "certificate_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                                "protocol_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                                "key_exchange_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                                "cipher_strength_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                                "warnings": {
                                    "type": "array",
                                    "items": { "type": "string" }
                                }
                            }
                        }
                    }
                },
                "http": {
                    "type": ["object", "null"],
                    "description": "HTTP analysis",
                    "properties": {
                        "http_headers": {
                            "type": ["object", "null"],
                            "description": "HTTP security headers analysis",
                            "properties": {
                                "hsts": { "type": "object" },
                                "hpkp": { "type": "object" },
                                "csp": { "type": "object" },
                                "x_frame_options": { "type": "object" },
                                "x_content_type_options": { "type": "object" }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Get schema for a specific section
    pub fn get_protocol_schema() -> Value {
        json!({
            "type": "object",
            "required": ["protocol", "supported", "inconclusive", "preferred", "ciphers_count"],
            "properties": {
                "protocol": {
                    "type": "string",
                    "enum": ["SSLv2", "SSLv3", "TLS10", "TLS11", "TLS12", "TLS13", "QUIC"]
                },
                "supported": { "type": "boolean" },
                "inconclusive": { "type": "boolean" },
                "preferred": { "type": "boolean" },
                "ciphers_count": { "type": "integer", "minimum": 0 },
                "handshake_time_ms": { "type": ["integer", "null"], "minimum": 0 },
                "heartbeat_enabled": { "type": ["boolean", "null"] },
                "session_resumption_caching": { "type": ["boolean", "null"] },
                "session_resumption_tickets": { "type": ["boolean", "null"] },
                "secure_renegotiation": { "type": ["boolean", "null"] }
            }
        })
    }

    /// Get schema for vulnerability entry
    pub fn get_vulnerability_schema() -> Value {
        json!({
            "type": "object",
            "required": ["vuln_type", "vulnerable", "inconclusive", "details", "severity"],
            "properties": {
                "vuln_type": { "type": "string" },
                "vulnerable": { "type": "boolean" },
                "inconclusive": { "type": "boolean" },
                "details": { "type": "string" },
                "severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"]
                },
                "description": { "type": "string" },
                "cve": { "type": ["string", "null"] },
                "cwe": { "type": ["string", "null"] },
                "cvss_score": { "type": "number", "minimum": 0.0, "maximum": 10.0 }
            }
        })
    }

    /// Validate JSON data against schema
    pub fn validate(data: &Value) -> Result<(), Vec<String>> {
        let _schema = Self::get_schema();
        let mut errors = Vec::new();

        // Basic validation (simplified)
        let obj = if let Some(obj) = data.as_object() {
            obj
        } else {
            errors.push("Root must be an object".to_string());
            return Err(errors);
        };

        // Check required fields
        let required = vec![
            "target",
            "scan_time_ms",
            "protocols",
            "ciphers",
            "vulnerabilities",
        ];
        for field in required {
            if !obj.contains_key(field) {
                errors.push(format!("Missing required field: {}", field));
            }
        }

        // Validate target structure
        if let Some(target) = obj.get("target")
            && !target.is_string()
        {
            errors.push("Target must be a string".to_string());
        }

        if let Some(scan_time_ms) = obj.get("scan_time_ms")
            && !scan_time_ms.is_u64()
        {
            errors.push("scan_time_ms must be a non-negative integer".to_string());
        }

        if let Some(ciphers) = obj.get("ciphers")
            && !ciphers.is_object()
        {
            errors.push("ciphers must be an object".to_string());
        }

        for field in ["certificate_chain", "rating", "http"] {
            if let Some(value) = obj.get(field)
                && !(value.is_object() || value.is_null())
            {
                errors.push(format!("{} must be an object or null", field));
            }
        }

        // Validate protocols array
        if let Some(protocols) = obj.get("protocols") {
            if let Some(protocols_arr) = protocols.as_array() {
                for (idx, protocol) in protocols_arr.iter().enumerate() {
                    if let Some(proto_obj) = protocol.as_object() {
                        if [
                            "protocol",
                            "supported",
                            "inconclusive",
                            "preferred",
                            "ciphers_count",
                        ]
                        .iter()
                        .any(|field| !proto_obj.contains_key(*field))
                        {
                            errors
                                .push(format!("Protocol at index {} missing required fields", idx));
                        }
                        if !proto_obj.get("protocol").is_some_and(|value| {
                            matches!(
                                value.as_str(),
                                Some(
                                    "SSLv2"
                                        | "SSLv3"
                                        | "TLS10"
                                        | "TLS11"
                                        | "TLS12"
                                        | "TLS13"
                                        | "QUIC"
                                )
                            )
                        }) {
                            errors.push(format!("Protocol at index {} has invalid protocol", idx));
                        }
                        for field in ["supported", "inconclusive", "preferred"] {
                            if !proto_obj.get(field).is_some_and(Value::is_boolean) {
                                errors.push(format!(
                                    "Protocol at index {} field {} must be boolean",
                                    idx, field
                                ));
                            }
                        }
                        if !proto_obj.get("ciphers_count").is_some_and(Value::is_u64) {
                            errors.push(format!(
                                "Protocol at index {} field ciphers_count must be a non-negative integer",
                                idx
                            ));
                        }
                    } else {
                        errors.push(format!("Protocol at index {} must be an object", idx));
                    }
                }
            } else {
                errors.push("protocols must be an array".to_string());
            }
        }

        if let Some(vulnerabilities) = obj.get("vulnerabilities") {
            if let Some(vulnerabilities_arr) = vulnerabilities.as_array() {
                for (idx, vulnerability) in vulnerabilities_arr.iter().enumerate() {
                    if let Some(vuln_obj) = vulnerability.as_object() {
                        if [
                            "vuln_type",
                            "vulnerable",
                            "inconclusive",
                            "details",
                            "severity",
                        ]
                        .iter()
                        .any(|field| !vuln_obj.contains_key(*field))
                        {
                            errors.push(format!(
                                "Vulnerability at index {} missing required fields",
                                idx
                            ));
                        }
                        if !vuln_obj.get("vuln_type").is_some_and(Value::is_string) {
                            errors.push(format!(
                                "Vulnerability at index {} field vuln_type must be a string",
                                idx
                            ));
                        }
                        for field in ["vulnerable", "inconclusive"] {
                            if !vuln_obj.get(field).is_some_and(Value::is_boolean) {
                                errors.push(format!(
                                    "Vulnerability at index {} field {} must be boolean",
                                    idx, field
                                ));
                            }
                        }
                        if !vuln_obj.get("details").is_some_and(Value::is_string) {
                            errors.push(format!(
                                "Vulnerability at index {} field details must be a string",
                                idx
                            ));
                        }
                        if !vuln_obj.get("severity").is_some_and(|value| {
                            matches!(
                                value.as_str(),
                                Some("Critical" | "High" | "Medium" | "Low" | "Info")
                            )
                        }) {
                            errors.push(format!(
                                "Vulnerability at index {} has invalid severity",
                                idx
                            ));
                        }
                    } else {
                        errors.push(format!("Vulnerability at index {} must be an object", idx));
                    }
                }
            } else {
                errors.push("vulnerabilities must be an array".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Export schema to file
    pub fn export_schema(path: &str) -> std::io::Result<()> {
        let schema = Self::get_schema();
        let schema_str = serde_json::to_string_pretty(&schema)?;
        std::fs::write(path, schema_str)?;
        Ok(())
    }
}

/// Schema validation result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::scanner::ScanResults;
    use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

    #[test]
    fn test_schema_generation() {
        let schema = CipherRunSchema::get_schema();
        assert!(schema.is_object());
        assert!(schema.get("$schema").is_some());
        assert!(schema.get("properties").is_some());
    }

    #[test]
    fn test_validation_valid_data() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_missing_fields() {
        let data = json!({
            "scan_time_ms": 100
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("target")));
    }

    #[test]
    fn test_validation_target_not_string() {
        let data = json!({
            "target": {
                "hostname": "example.com",
                "port": 443,
                "ip": "93.184.216.34"
            },
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Target must be a string")));
    }

    #[test]
    fn test_protocol_schema() {
        let schema = CipherRunSchema::get_protocol_schema();
        assert!(schema.is_object());
        assert!(schema.get("properties").is_some());
    }

    #[test]
    fn test_vulnerability_schema_required_fields() {
        let schema = CipherRunSchema::get_vulnerability_schema();
        let required = schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("required should be array");
        let required_values: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_values.contains(&"vuln_type"));
        assert!(required_values.contains(&"vulnerable"));
        assert!(required_values.contains(&"inconclusive"));
        assert!(required_values.contains(&"details"));
        assert!(required_values.contains(&"severity"));
    }

    #[test]
    fn test_schema_contains_title() {
        let schema = CipherRunSchema::get_schema();
        let title = schema.get("title").and_then(|v| v.as_str());
        assert_eq!(title, Some("CipherRun Scan Results"));
    }

    #[test]
    fn test_schema_uses_serialized_result_group_names() {
        let schema = CipherRunSchema::get_schema();
        let properties = schema
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("schema properties should be an object");

        assert!(properties.contains_key("http"));
        assert!(!properties.contains_key("http_headers"));
        assert!(properties.contains_key("certificate_chain"));
        assert!(!properties.contains_key("certificate"));
        assert!(
            properties
                .get("http")
                .and_then(|v| v.get("properties"))
                .and_then(|v| v.get("http_headers"))
                .is_some()
        );
        assert!(
            properties
                .get("rating")
                .and_then(|v| v.get("properties"))
                .and_then(|v| v.get("ssl_rating"))
                .is_some()
        );
        let grade_values = properties
            .get("rating")
            .and_then(|v| v.get("properties"))
            .and_then(|v| v.get("ssl_rating"))
            .and_then(|v| v.get("properties"))
            .and_then(|v| v.get("grade"))
            .and_then(|v| v.get("enum"))
            .and_then(|v| v.as_array())
            .expect("rating grade enum should be present");
        assert!(grade_values.iter().any(|v| v == "Unverified"));
        assert!(!grade_values.iter().any(|v| v == "B+"));
    }

    #[test]
    fn test_certificate_chain_schema_includes_leaf_fields() {
        let schema = CipherRunSchema::get_schema();
        let certificate_chain = schema
            .get("properties")
            .and_then(|v| v.get("certificate_chain"))
            .and_then(|v| v.get("properties"))
            .and_then(|v| v.get("chain"))
            .and_then(|v| v.get("properties"))
            .and_then(|v| v.get("certificates"))
            .and_then(|v| v.get("items"))
            .and_then(|v| v.get("properties"))
            .and_then(|v| v.as_object())
            .expect("certificate leaf schema should be present");

        for field in [
            "subject",
            "issuer",
            "serial_number",
            "public_key_size",
            "rsa_exponent",
            "is_ca",
            "fingerprint_sha256",
            "certificate_transparency",
        ] {
            assert!(
                certificate_chain.contains_key(field),
                "missing field {field}"
            );
        }
    }

    #[test]
    fn test_validation_non_object_root() {
        let data = json!("not-an-object");
        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Root must be an object")));
    }

    #[test]
    fn test_export_schema_writes_file() {
        let path = std::env::temp_dir().join("cipherrun-schema.json");
        CipherRunSchema::export_schema(path.to_str().unwrap()).expect("export should succeed");
        let contents = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(contents.contains("CipherRun Scan Results"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_protocol_schema_includes_tls12() {
        let schema = CipherRunSchema::get_protocol_schema();
        let enum_values = schema
            .get("properties")
            .and_then(|p| p.get("protocol"))
            .and_then(|p| p.get("enum"))
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(enum_values.iter().any(|v| v == "TLS12"));
        assert!(!enum_values.iter().any(|v| v == "TLS 1.2"));
    }

    #[test]
    fn test_validation_target_number() {
        let data = json!({
            "target": 443,
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Target must be a string")));
    }

    #[test]
    fn test_validation_rejects_negative_scan_time() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": -1,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("scan_time_ms must be a non-negative integer"))
        );
    }

    #[test]
    fn test_validation_accepts_serialized_scan_results_with_inconclusive_states() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 100,
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: false,
                inconclusive: true,
                preferred: false,
                ciphers_count: 0,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: false,
                inconclusive: true,
                details: "probe timed out".to_string(),
                cve: None,
                cwe: Some("CWE-200".to_string()),
                severity: Severity::High,
            }],
            ..Default::default()
        };

        let data = serde_json::to_value(results).expect("scan results should serialize");
        let result = CipherRunSchema::validate(&data);
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn test_validation_rejects_protocol_missing_inconclusive() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [{
                "protocol": "TLS12",
                "supported": false,
                "preferred": false,
                "ciphers_count": 0
            }],
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Protocol at index 0")));
    }

    #[test]
    fn test_validation_rejects_protocols_not_array() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": "TLS12",
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("protocols must be an array"))
        );
    }

    #[test]
    fn test_validation_rejects_protocol_item_not_object() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": ["TLS12"],
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Protocol at index 0 must be an object"))
        );
    }

    #[test]
    fn test_validation_rejects_protocol_invalid_field_types() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [{
                "protocol": "TLS 1.2",
                "supported": "false",
                "inconclusive": false,
                "preferred": false,
                "ciphers_count": -1
            }],
            "ciphers": {},
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Protocol at index 0 has invalid protocol"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("field supported must be boolean"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("field ciphers_count must be a non-negative integer"))
        );
    }

    #[test]
    fn test_validation_rejects_vulnerability_missing_details() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": [{
                "vuln_type": "Heartbleed",
                "vulnerable": false,
                "inconclusive": true,
                "severity": "High"
            }]
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Vulnerability at index 0"))
        );
    }

    #[test]
    fn test_validation_rejects_vulnerability_invalid_field_types() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": [{
                "vuln_type": 7,
                "vulnerable": "false",
                "inconclusive": false,
                "details": null,
                "severity": "banana"
            }]
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("field vuln_type must be a string"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("field vulnerable must be boolean"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("field details must be a string"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Vulnerability at index 0 has invalid severity"))
        );
    }

    #[test]
    fn test_validation_rejects_vulnerabilities_not_array() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": "Heartbleed"
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("vulnerabilities must be an array"))
        );
    }

    #[test]
    fn test_validation_rejects_ciphers_not_object() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": [],
            "vulnerabilities": []
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("ciphers must be an object"))
        );
    }

    #[test]
    fn test_validation_rejects_optional_result_groups_with_wrong_types() {
        let data = json!({
            "target": "example.com:443",
            "scan_time_ms": 100,
            "protocols": [],
            "ciphers": {},
            "vulnerabilities": [],
            "certificate_chain": [],
            "rating": "A",
            "http": false
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("certificate_chain must be an object or null"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("rating must be an object or null"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("http must be an object or null"))
        );
    }

    #[test]
    fn test_validation_result_helpers() {
        let ok = ValidationResult::success();
        assert!(ok.valid);
        assert!(ok.errors.is_empty());

        let fail = ValidationResult::failure(vec!["err".to_string()]);
        assert!(!fail.valid);
        assert_eq!(fail.errors.len(), 1);
    }
}
