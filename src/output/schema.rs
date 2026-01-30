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
            "required": ["target", "timestamp", "scan_version"],
            "properties": {
                "target": {
                    "type": "object",
                    "description": "Target information",
                    "required": ["hostname", "port", "ip"],
                    "properties": {
                        "hostname": { "type": "string" },
                        "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                        "ip": { "type": "string", "pattern": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$" }
                    }
                },
                "timestamp": {
                    "type": "string",
                    "format": "date-time",
                    "description": "ISO 8601 timestamp of scan start"
                },
                "scan_version": {
                    "type": "string",
                    "description": "CipherRun version"
                },
                "protocols": {
                    "type": "array",
                    "description": "Supported TLS/SSL protocols",
                    "items": {
                        "type": "object",
                        "required": ["protocol", "supported"],
                        "properties": {
                            "protocol": {
                                "type": "string",
                                "enum": ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "QUIC"]
                            },
                            "supported": { "type": "boolean" },
                            "preferred": { "type": "boolean" },
                            "ciphers_count": { "type": "integer", "minimum": 0 }
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
                "certificate": {
                    "type": "object",
                    "description": "Certificate chain information",
                    "properties": {
                        "subject": { "type": "string" },
                        "issuer": { "type": "string" },
                        "valid_from": { "type": "string" },
                        "valid_until": { "type": "string" },
                        "san": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "signature_algorithm": { "type": "string" },
                        "public_key_algorithm": { "type": "string" },
                        "key_size": { "type": "integer" },
                        "validation": {
                            "type": "object",
                            "properties": {
                                "valid": { "type": "boolean" },
                                "not_expired": { "type": "boolean" },
                                "hostname_match": { "type": "boolean" },
                                "trust_chain_valid": { "type": "boolean" }
                            }
                        }
                    }
                },
                "vulnerabilities": {
                    "type": "array",
                    "description": "Detected vulnerabilities",
                    "items": {
                        "type": "object",
                        "required": ["vuln_type", "vulnerable", "severity"],
                        "properties": {
                            "vuln_type": { "type": "string" },
                            "vulnerable": { "type": "boolean" },
                            "severity": {
                                "type": "string",
                                "enum": ["Critical", "High", "Medium", "Low", "Info"]
                            },
                            "description": { "type": "string" },
                            "cve": { "type": "string" },
                            "cvss_score": { "type": "number", "minimum": 0.0, "maximum": 10.0 }
                        }
                    }
                },
                "rating": {
                    "type": "object",
                    "description": "SSL Labs style rating",
                    "properties": {
                        "grade": {
                            "type": "string",
                            "pattern": "^[A-F]([+-])?|T|M$"
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
                },
                "http_headers": {
                    "type": "object",
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
        })
    }

    /// Get schema for a specific section
    pub fn get_protocol_schema() -> Value {
        json!({
            "type": "object",
            "required": ["protocol", "supported"],
            "properties": {
                "protocol": {
                    "type": "string",
                    "enum": ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "QUIC"]
                },
                "supported": { "type": "boolean" },
                "preferred": { "type": "boolean" },
                "ciphers_count": { "type": "integer", "minimum": 0 }
            }
        })
    }

    /// Get schema for vulnerability entry
    pub fn get_vulnerability_schema() -> Value {
        json!({
            "type": "object",
            "required": ["vuln_type", "vulnerable", "severity"],
            "properties": {
                "vuln_type": { "type": "string" },
                "vulnerable": { "type": "boolean" },
                "severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"]
                },
                "description": { "type": "string" },
                "cve": { "type": "string" },
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
        let required = vec!["target", "timestamp", "scan_version"];
        for field in required {
            if !obj.contains_key(field) {
                errors.push(format!("Missing required field: {}", field));
            }
        }

        // Validate target structure
        if let Some(target) = obj.get("target") {
            if let Some(target_obj) = target.as_object() {
                for required_field in &["hostname", "port", "ip"] {
                    if !target_obj.contains_key(*required_field) {
                        errors.push(format!(
                            "Missing required field in target: {}",
                            required_field
                        ));
                    }
                }
            } else {
                errors.push("Target must be an object".to_string());
            }
        }

        // Validate protocols array
        if let Some(protocols) = obj.get("protocols")
            && let Some(protocols_arr) = protocols.as_array()
        {
            for (idx, protocol) in protocols_arr.iter().enumerate() {
                if let Some(proto_obj) = protocol.as_object()
                    && (!proto_obj.contains_key("protocol") || !proto_obj.contains_key("supported"))
                {
                    errors.push(format!("Protocol at index {} missing required fields", idx));
                }
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
            "target": {
                "hostname": "example.com",
                "port": 443,
                "ip": "93.184.216.34"
            },
            "timestamp": "2024-01-01T00:00:00Z",
            "scan_version": "1.0.0"
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_missing_fields() {
        let data = json!({
            "timestamp": "2024-01-01T00:00:00Z"
        });

        let result = CipherRunSchema::validate(&data);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("target")));
    }

    #[test]
    fn test_protocol_schema() {
        let schema = CipherRunSchema::get_protocol_schema();
        assert!(schema.is_object());
        assert!(schema.get("properties").is_some());
    }
}
