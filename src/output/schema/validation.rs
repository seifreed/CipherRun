use serde_json::Value;

pub(super) fn validate(data: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    let obj = if let Some(obj) = data.as_object() {
        obj
    } else {
        errors.push("Root must be an object".to_string());
        return Err(errors);
    };

    for field in [
        "schema_version",
        "scanner_version",
        "ruleset_version",
        "data_version",
        "target",
        "scan_time_ms",
        "protocols",
        "ciphers",
        "vulnerabilities",
    ] {
        if !obj.contains_key(field) {
            errors.push(format!("Missing required field: {}", field));
        }
    }

    if let Some(schema_version) = obj.get("schema_version")
        && schema_version.as_str() != Some(crate::scanner::results::OUTPUT_SCHEMA_VERSION)
    {
        errors.push(format!(
            "schema_version must be {}",
            crate::scanner::results::OUTPUT_SCHEMA_VERSION
        ));
    }

    for field in ["scanner_version", "ruleset_version", "data_version"] {
        if let Some(value) = obj.get(field)
            && value.as_str().is_none_or(|value| value.is_empty())
        {
            errors.push(format!("{} must be a non-empty string", field));
        }
    }

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

    if let Some(protocols) = obj.get("protocols") {
        validate_protocols(protocols, &mut errors);
    }

    if let Some(vulnerabilities) = obj.get("vulnerabilities") {
        validate_vulnerabilities(vulnerabilities, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_protocols(protocols: &Value, errors: &mut Vec<String>) {
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
                    errors.push(format!("Protocol at index {} missing required fields", idx));
                }
                if !proto_obj.get("protocol").is_some_and(|value| {
                    matches!(
                        value.as_str(),
                        Some("SSLv2" | "SSLv3" | "TLS10" | "TLS11" | "TLS12" | "TLS13" | "QUIC")
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

fn validate_vulnerabilities(vulnerabilities: &Value, errors: &mut Vec<String>) {
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
