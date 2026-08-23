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

    let schema_version = obj.get("schema_version").and_then(Value::as_str);
    if obj
        .get("schema_version")
        .is_some_and(|value| !value.is_string())
    {
        errors.push("schema_version must be a string".to_string());
    }
    if let Some(schema_version) = schema_version
        && !crate::scanner::results::SUPPORTED_OUTPUT_SCHEMA_VERSIONS.contains(&schema_version)
    {
        errors.push(format!(
            "unsupported schema_version {}; supported versions: {}",
            schema_version,
            crate::scanner::results::SUPPORTED_OUTPUT_SCHEMA_VERSIONS.join(", ")
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
        validate_vulnerabilities(
            vulnerabilities,
            schema_version == Some(crate::scanner::results::OUTPUT_SCHEMA_VERSION),
            &mut errors,
        );
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

fn validate_vulnerabilities(
    vulnerabilities: &Value,
    require_enriched_finding: bool,
    errors: &mut Vec<String>,
) {
    if let Some(vulnerabilities_arr) = vulnerabilities.as_array() {
        for (idx, vulnerability) in vulnerabilities_arr.iter().enumerate() {
            if let Some(vuln_obj) = vulnerability.as_object() {
                let mut required = vec![
                    "vuln_type",
                    "vulnerable",
                    "inconclusive",
                    "details",
                    "severity",
                ];
                if require_enriched_finding {
                    required.extend([
                        "finding_id",
                        "status",
                        "detection_method",
                        "confidence",
                        "evidence",
                    ]);
                }
                if required.iter().any(|field| !vuln_obj.contains_key(*field)) {
                    errors.push(format!(
                        "Vulnerability at index {} missing required fields",
                        idx
                    ));
                }
                if require_enriched_finding {
                    validate_finding_metadata(idx, vuln_obj, errors);
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

fn validate_finding_metadata(
    idx: usize,
    vulnerability: &serde_json::Map<String, Value>,
    errors: &mut Vec<String>,
) {
    if !vulnerability
        .get("finding_id")
        .and_then(Value::as_str)
        .is_some_and(|value| {
            value
                .strip_prefix("CR-TLS-")
                .and_then(|value| value.strip_suffix("-001"))
                .is_some_and(|name| {
                    !name.is_empty()
                        && name.bytes().all(|byte| {
                            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
        })
    {
        errors.push(format!(
            "Vulnerability at index {} has invalid finding_id",
            idx
        ));
    }
    if !vulnerability.get("status").is_some_and(|value| {
        matches!(
            value.as_str(),
            Some(
                "confirmed_vulnerable"
                    | "potential_exposure"
                    | "not_vulnerable"
                    | "inconclusive"
                    | "not_applicable"
                    | "not_executed"
            )
        )
    }) {
        errors.push(format!("Vulnerability at index {} has invalid status", idx));
    }
    if let (Some(status), Some(vulnerable), Some(inconclusive)) = (
        vulnerability.get("status").and_then(Value::as_str),
        vulnerability.get("vulnerable").and_then(Value::as_bool),
        vulnerability.get("inconclusive").and_then(Value::as_bool),
    ) {
        let expected = match (vulnerable, inconclusive) {
            (true, false) => "confirmed_vulnerable",
            (true, true) => "potential_exposure",
            (false, true) => "inconclusive",
            (false, false)
                if vulnerability.get("vuln_type").and_then(Value::as_str) == Some("GREASE") =>
            {
                "not_applicable"
            }
            (false, false) => "not_vulnerable",
        };
        if status != "not_executed" && status != expected {
            errors.push(format!(
                "Vulnerability at index {} status conflicts with legacy flags",
                idx
            ));
        }
    }
    if !vulnerability.get("detection_method").is_some_and(|value| {
        matches!(
            value.as_str(),
            Some(
                "active_probe"
                    | "protocol_negotiation"
                    | "configuration_inference"
                    | "timing_analysis"
                    | "heuristic"
            )
        )
    }) {
        errors.push(format!(
            "Vulnerability at index {} has invalid detection_method",
            idx
        ));
    }
    if !vulnerability
        .get("confidence")
        .is_some_and(|value| matches!(value.as_str(), Some("low" | "medium" | "high")))
    {
        errors.push(format!(
            "Vulnerability at index {} has invalid confidence",
            idx
        ));
    }

    let Some(evidence) = vulnerability.get("evidence").and_then(Value::as_object) else {
        errors.push(format!(
            "Vulnerability at index {} evidence must be an object",
            idx
        ));
        return;
    };
    let required = [
        "affected_ip",
        "port",
        "sni",
        "protocol",
        "cipher_suite",
        "observed",
        "expected_result",
        "attempts",
        "probe_version",
        "limitations",
        "references",
        "remediation",
        "potentially_intrusive",
    ];
    if required.iter().any(|field| !evidence.contains_key(*field)) {
        errors.push(format!(
            "Vulnerability at index {} evidence missing required fields",
            idx
        ));
        return;
    }

    for field in [
        "observed",
        "expected_result",
        "probe_version",
        "remediation",
    ] {
        if !evidence.get(field).is_some_and(Value::is_string) {
            errors.push(format!(
                "Vulnerability at index {} evidence field {} must be a string",
                idx, field
            ));
        }
    }
    for field in ["limitations", "references"] {
        if !evidence.get(field).is_some_and(|value| {
            value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
        }) {
            errors.push(format!(
                "Vulnerability at index {} evidence field {} must be an array of strings",
                idx, field
            ));
        }
    }
    for field in ["sni", "protocol", "cipher_suite"] {
        if !evidence
            .get(field)
            .is_some_and(|value| value.is_null() || value.is_string())
        {
            errors.push(format!(
                "Vulnerability at index {} evidence field {} must be null or a string",
                idx, field
            ));
        }
    }
    if !evidence.get("affected_ip").is_some_and(|value| {
        value.is_null()
            || value
                .as_str()
                .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
    }) {
        errors.push(format!(
            "Vulnerability at index {} evidence field affected_ip must be null or an IP address",
            idx
        ));
    }
    if !evidence
        .get("potentially_intrusive")
        .is_some_and(Value::is_boolean)
    {
        errors.push(format!(
            "Vulnerability at index {} evidence field potentially_intrusive must be boolean",
            idx
        ));
    }
    if !evidence
        .get("attempts")
        .is_some_and(|value| value.is_null() || value.as_u64().is_some_and(|attempts| attempts > 0))
    {
        errors.push(format!(
            "Vulnerability at index {} evidence field attempts must be null or positive",
            idx
        ));
    }
    if !evidence.get("port").is_some_and(|value| {
        value.is_null()
            || value
                .as_u64()
                .is_some_and(|port| (1..=65535).contains(&port))
    }) {
        errors.push(format!(
            "Vulnerability at index {} evidence field port must be null or 1-65535",
            idx
        ));
    }
}
