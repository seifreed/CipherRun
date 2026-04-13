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
            "terminal" | "text" => Ok(self.format_terminal(comparison)),
            _ => Err(crate::TlsError::DatabaseError(format!(
                "Unknown format: {}",
                format
            ))),
        }
    }

    fn format_terminal(&self, comp: &ScanComparison) -> String {
        let mut output = String::new();

        output.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                        SCAN COMPARISON                             ║\n");
        output
            .push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        // Scan info
        output.push_str(&format!(
            "Scan 1: {} (ID: {})\n",
            comp.scan_1.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            comp.scan_1.scan_id.unwrap_or(0)
        ));
        output.push_str(&format!(
            "Scan 2: {} (ID: {})\n",
            comp.scan_2.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            comp.scan_2.scan_id.unwrap_or(0)
        ));
        output.push_str(&format!(
            "Target: {}\n\n",
            canonical_target(&comp.scan_1.target_hostname, comp.scan_1.target_port as u16)
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
                "Overall: {} ({}) → {} ({})\n\n",
                comp.rating_diff
                    .scan_1_grade
                    .as_ref()
                    .unwrap_or(&"N/A".to_string()),
                comp.rating_diff.scan_1_score.unwrap_or(0),
                comp.rating_diff
                    .scan_2_grade
                    .as_ref()
                    .unwrap_or(&"N/A".to_string()),
                comp.rating_diff.scan_2_score.unwrap_or(0)
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
                    "  Key Size: {} bits\n",
                    cert1.key_size.unwrap_or(0)
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
                    "  Key Size: {} bits\n",
                    cert2.key_size.unwrap_or(0)
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

        output
    }
}
