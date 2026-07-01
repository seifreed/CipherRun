// Formatting methods for ScanComparator

use super::{CipherDetailInfo, ScanComparator, ScanComparison};
use crate::output::scanner_formatter::truncate_with_ellipsis;
use crate::utils::network::canonical_target;

fn format_cipher_detail(cipher: &CipherDetailInfo) -> String {
    let bits = cipher
        .bits
        .map(|value| value.to_string())
        .unwrap_or_else(|| "N/A".to_string());

    format!(
        "{} [{}] strength={} fs={} key_exchange={} authentication={} encryption={} mac={} bits={}",
        cipher.name.as_str(),
        cipher.protocol.as_str(),
        cipher.strength.as_str(),
        cipher.forward_secrecy,
        cipher.key_exchange.as_deref().unwrap_or("N/A"),
        cipher.authentication.as_deref().unwrap_or("N/A"),
        cipher.encryption.as_deref().unwrap_or("N/A"),
        cipher.mac.as_deref().unwrap_or("N/A"),
        bits
    )
}

fn format_rating_detail(
    score: Option<i32>,
    grade: Option<&str>,
    rationale: Option<&str>,
) -> String {
    let score = score
        .map(|value| value.to_string())
        .unwrap_or_else(|| "N/A".to_string());
    let grade = grade.unwrap_or("N/A");
    let rationale = rationale
        .map(|value| truncate_with_ellipsis(value, 96))
        .unwrap_or_else(|| "N/A".to_string());

    format!("score={} grade={} rationale={}", score, grade, rationale)
}

fn format_overall_rating(grade: Option<&String>, score: Option<i32>) -> String {
    let grade = grade.map(String::as_str).unwrap_or("N/A");
    let score = score
        .map(|value| value.to_string())
        .unwrap_or_else(|| "N/A".to_string());
    format!("{grade} ({score})")
}

fn format_key_size_bits(size: Option<i32>) -> String {
    size.map(|value| format!("{value} bits"))
        .unwrap_or_else(|| "N/A".to_string())
}

impl ScanComparator {
    /// Format comparison as string
    pub fn format_comparison(
        &self,
        comparison: &ScanComparison,
        format: &str,
    ) -> crate::Result<String> {
        match format.to_lowercase().as_str() {
            "json" => serde_json::to_string_pretty(comparison).map_err(|e| {
                crate::TlsError::DatabaseError(format!("JSON serialization failed: {}", e))
            }),
            "terminal" | "text" => Self::format_terminal(comparison),
            _ => Err(crate::TlsError::DatabaseError(format!(
                "Unknown format: {}",
                format
            ))),
        }
    }

    fn format_terminal(comp: &ScanComparison) -> crate::Result<String> {
        let mut output = String::new();
        let target_port = u16::try_from(comp.scan_1.target_port).map_err(|_| {
            crate::TlsError::DatabaseError(format!(
                "Invalid scan field target_port for scan {:?}: {}",
                comp.scan_1.scan_id, comp.scan_1.target_port
            ))
        })?;
        let scan_1_id = comp
            .scan_1
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan 1 missing scan_id".to_string()))?;
        let scan_2_id = comp
            .scan_2
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan 2 missing scan_id".to_string()))?;

        output.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                        SCAN COMPARISON                             ║\n");
        output
            .push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        // Scan info
        output.push_str(&format!(
            "Scan 1: {} (ID: {})\n",
            comp.scan_1.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            scan_1_id
        ));
        output.push_str(&format!(
            "Scan 2: {} (ID: {})\n",
            comp.scan_2.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            scan_2_id
        ));
        output.push_str(&format!(
            "Target: {}\n\n",
            canonical_target(&comp.scan_1.target_hostname, target_port)
        ));

        // Summary
        output.push_str("SUMMARY\n");
        output.push_str("───────────────────────────────────────────────────────────────────\n");
        output.push_str(&format!(
            "Total changes:        {}\n",
            comp.summary.total_changes
        ));
        output.push_str(&format!(
            "Protocol changes:     {}\n",
            comp.summary.protocol_changes
        ));
        output.push_str(&format!(
            "Cipher changes:       {}\n",
            comp.summary.cipher_changes
        ));
        output.push_str(&format!(
            "Certificate changes:  {}\n",
            comp.summary.certificate_changes
        ));
        output.push_str(&format!(
            "Vulnerability changes:{}\n",
            comp.summary.vulnerability_changes
        ));
        output.push_str(&format!(
            "Rating changes:       {}\n",
            comp.summary.rating_changes
        ));
        output.push_str(&format!(
            "Time between scans:   {} seconds\n\n",
            comp.summary.time_between_scans
        ));

        // Rating comparison
        let has_rating_changes = comp.rating_diff.overall_changed
            || comp
                .rating_diff
                .component_diffs
                .iter()
                .any(|component| component.changed);
        if has_rating_changes {
            output.push_str("RATING CHANGES\n");
            output
                .push_str("───────────────────────────────────────────────────────────────────\n");
            output.push_str(&format!(
                "Overall: {} → {}\n\n",
                format_overall_rating(
                    comp.rating_diff.scan_1_grade.as_ref(),
                    comp.rating_diff.scan_1_score
                ),
                format_overall_rating(
                    comp.rating_diff.scan_2_grade.as_ref(),
                    comp.rating_diff.scan_2_score
                )
            ));

            for component in &comp.rating_diff.component_diffs {
                if component.changed {
                    let mut changed_fields = Vec::new();
                    if component.scan_1_score != component.scan_2_score {
                        changed_fields.push("score");
                    }
                    if component.scan_1_grade != component.scan_2_grade {
                        changed_fields.push("grade");
                    }
                    if component.scan_1_rationale != component.scan_2_rationale {
                        changed_fields.push("rationale");
                    }

                    output.push_str(&format!("  {}:\n", component.category));
                    if !changed_fields.is_empty() {
                        output.push_str(&format!("    Fields: {}\n", changed_fields.join(", ")));
                    }
                    output.push_str(&format!(
                        "    Before: {}\n",
                        format_rating_detail(
                            component.scan_1_score,
                            component.scan_1_grade.as_deref(),
                            component.scan_1_rationale.as_deref()
                        )
                    ));
                    output.push_str(&format!(
                        "    After:  {}\n",
                        format_rating_detail(
                            component.scan_2_score,
                            component.scan_2_grade.as_deref(),
                            component.scan_2_rationale.as_deref()
                        )
                    ));
                }
            }
            output.push('\n');
        }

        // Protocol changes
        let has_protocol_changes = !comp.protocol_diff.added.is_empty()
            || !comp.protocol_diff.removed.is_empty()
            || comp.protocol_diff.preferred_change.is_some();
        if has_protocol_changes {
            output.push_str("PROTOCOL CHANGES\n");
            output
                .push_str("───────────────────────────────────────────────────────────────────\n");
            if !comp.protocol_diff.added.is_empty() {
                output.push_str("Added:\n");
                for proto in &comp.protocol_diff.added {
                    output.push_str(&format!("  + {}\n", proto));
                }
            }
            if !comp.protocol_diff.removed.is_empty() {
                output.push_str("Removed:\n");
                for proto in &comp.protocol_diff.removed {
                    output.push_str(&format!("  - {}\n", proto));
                }
            }
            if let Some((old_pref, new_pref)) = &comp.protocol_diff.preferred_change {
                output.push_str(&format!("Preferred: {:?} → {:?}\n", old_pref, new_pref));
            }
            output.push('\n');
        }

        // Cipher changes
        if !comp.cipher_diff.added.is_empty()
            || !comp.cipher_diff.removed.is_empty()
            || !comp.cipher_diff.changed.is_empty()
        {
            output.push_str("CIPHER SUITE CHANGES\n");
            output
                .push_str("───────────────────────────────────────────────────────────────────\n");
            if !comp.cipher_diff.added.is_empty() {
                output.push_str(&format!("Added ({}):\n", comp.cipher_diff.added.len()));
                for cipher in comp.cipher_diff.added.iter().take(5) {
                    output.push_str(&format!(
                        "  + {} [{}] ({})\n",
                        cipher.name, cipher.protocol, cipher.strength
                    ));
                }
                if comp.cipher_diff.added.len() > 5 {
                    output.push_str(&format!(
                        "  ... and {} more\n",
                        comp.cipher_diff.added.len() - 5
                    ));
                }
            }
            if !comp.cipher_diff.removed.is_empty() {
                output.push_str(&format!("Removed ({}):\n", comp.cipher_diff.removed.len()));
                for cipher in comp.cipher_diff.removed.iter().take(5) {
                    output.push_str(&format!(
                        "  - {} [{}] ({})\n",
                        cipher.name, cipher.protocol, cipher.strength
                    ));
                }
                if comp.cipher_diff.removed.len() > 5 {
                    output.push_str(&format!(
                        "  ... and {} more\n",
                        comp.cipher_diff.removed.len() - 5
                    ));
                }
            }
            if !comp.cipher_diff.changed.is_empty() {
                output.push_str(&format!("Changed ({}):\n", comp.cipher_diff.changed.len()));
                for cipher in comp.cipher_diff.changed.iter().take(5) {
                    output.push_str(&format!(
                        "  * {} [{}]\n",
                        cipher.current.name, cipher.current.protocol
                    ));
                    if !cipher.changed_fields.is_empty() {
                        output.push_str(&format!(
                            "    Fields: {}\n",
                            cipher.changed_fields.join(", ")
                        ));
                    }
                    output.push_str(&format!(
                        "    Before: {}\n",
                        format_cipher_detail(&cipher.previous)
                    ));
                    output.push_str(&format!(
                        "    After:  {}\n",
                        format_cipher_detail(&cipher.current)
                    ));
                }
                if comp.cipher_diff.changed.len() > 5 {
                    output.push_str(&format!(
                        "  ... and {} more\n",
                        comp.cipher_diff.changed.len() - 5
                    ));
                }
            }
            output.push('\n');
        }

        // Certificate changes
        if comp.certificate_diff.fingerprint_changed {
            output.push_str("CERTIFICATE CHANGES\n");
            output
                .push_str("───────────────────────────────────────────────────────────────────\n");
            if let Some(cert1) = &comp.certificate_diff.scan_1_cert {
                output.push_str("Old Certificate:\n");
                output.push_str(&format!("  Subject:  {}\n", cert1.subject));
                output.push_str(&format!("  Issuer:   {}\n", cert1.issuer));
                output.push_str(&format!(
                    "  Expires:  {}\n",
                    cert1.not_after.format("%Y-%m-%d")
                ));
                output.push_str(&format!(
                    "  Key Size: {}\n",
                    format_key_size_bits(cert1.key_size)
                ));
            }
            if let Some(cert2) = &comp.certificate_diff.scan_2_cert {
                output.push_str("New Certificate:\n");
                output.push_str(&format!("  Subject:  {}\n", cert2.subject));
                output.push_str(&format!("  Issuer:   {}\n", cert2.issuer));
                output.push_str(&format!(
                    "  Expires:  {}\n",
                    cert2.not_after.format("%Y-%m-%d")
                ));
                output.push_str(&format!(
                    "  Key Size: {}\n",
                    format_key_size_bits(cert2.key_size)
                ));
            }
            output.push('\n');
        }

        // Vulnerability changes
        if !comp.vulnerability_diff.new.is_empty()
            || !comp.vulnerability_diff.resolved.is_empty()
            || !comp.vulnerability_diff.changed.is_empty()
        {
            output.push_str("VULNERABILITY CHANGES\n");
            output
                .push_str("───────────────────────────────────────────────────────────────────\n");
            if !comp.vulnerability_diff.new.is_empty() {
                output.push_str("New Vulnerabilities:\n");
                for vuln in &comp.vulnerability_diff.new {
                    output.push_str(&format!("  + {} [{}]\n", vuln.vuln_type, vuln.severity));
                }
            }
            if !comp.vulnerability_diff.resolved.is_empty() {
                output.push_str("Resolved Vulnerabilities:\n");
                for vuln in &comp.vulnerability_diff.resolved {
                    output.push_str(&format!("  - {} [{}]\n", vuln.vuln_type, vuln.severity));
                }
            }
            if !comp.vulnerability_diff.changed.is_empty() {
                output.push_str("Changed Vulnerabilities:\n");
                for vuln in &comp.vulnerability_diff.changed {
                    output.push_str(&format!("  * {} [{}]\n", vuln.vuln_type, vuln.severity));
                }
            }
            output.push('\n');
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ScanRecord;
    use crate::db::analytics::scan_comparator::{
        CertificateDiff, CipherDiff, ComparisonSummary, ProtocolDiff, RatingDiff, VulnerabilityDiff,
    };

    fn minimal_comparison() -> ScanComparison {
        let scan = ScanRecord::new("example.com".to_string(), 443);
        ScanComparison {
            scan_1: scan.clone(),
            scan_2: scan,
            protocol_diff: ProtocolDiff {
                added: Vec::new(),
                removed: Vec::new(),
                unchanged: Vec::new(),
                preferred_change: None,
            },
            cipher_diff: CipherDiff {
                added: Vec::new(),
                removed: Vec::new(),
                unchanged: Vec::new(),
                changed: Vec::new(),
            },
            certificate_diff: CertificateDiff {
                fingerprint_changed: false,
                subject_changed: false,
                issuer_changed: false,
                key_size_changed: false,
                expiry_changed: false,
                scan_1_cert: None,
                scan_2_cert: None,
            },
            vulnerability_diff: VulnerabilityDiff {
                resolved: Vec::new(),
                new: Vec::new(),
                changed: Vec::new(),
                unchanged: Vec::new(),
            },
            rating_diff: RatingDiff {
                overall_changed: false,
                scan_1_grade: None,
                scan_1_score: None,
                scan_2_grade: None,
                scan_2_score: None,
                component_diffs: Vec::new(),
            },
            summary: ComparisonSummary {
                total_changes: 0,
                protocol_changes: 0,
                cipher_changes: 0,
                certificate_changes: 0,
                vulnerability_changes: 0,
                rating_changes: 0,
                time_between_scans: 0,
            },
        }
    }

    #[test]
    fn terminal_formatter_rejects_invalid_target_port() {
        let mut comparison = minimal_comparison();
        comparison.scan_1.target_port = 70_000;

        let err = ScanComparator::format_terminal(&comparison)
            .expect_err("invalid target port should fail");

        assert!(err.to_string().contains("target_port"));
    }

    #[test]
    fn terminal_formatter_rejects_missing_scan_id() {
        let mut comparison = minimal_comparison();
        comparison.scan_1.scan_id = None;

        let err =
            ScanComparator::format_terminal(&comparison).expect_err("missing scan id should fail");

        assert!(err.to_string().contains("missing scan_id"));
    }
}
