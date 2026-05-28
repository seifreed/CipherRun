// ChangeTracker vulnerability-change detection and matching

use super::*;

impl ChangeTracker {
    pub(super) async fn detect_vulnerability_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let vulns1 = self.get_vulnerabilities(scan_id_1).await?;
        let vulns2 = self.get_vulnerabilities(scan_id_2).await?;

        let mut changes = Vec::new();

        let mut grouped1: BTreeMap<String, Vec<&VulnerabilityRecord>> = BTreeMap::new();
        let mut grouped2: BTreeMap<String, Vec<&VulnerabilityRecord>> = BTreeMap::new();

        for vuln in &vulns1 {
            grouped1
                .entry(vuln.vulnerability_type.clone())
                .or_default()
                .push(vuln);
        }
        for vuln in &vulns2 {
            grouped2
                .entry(vuln.vulnerability_type.clone())
                .or_default()
                .push(vuln);
        }

        let vuln_types: BTreeSet<String> = grouped1
            .keys()
            .cloned()
            .chain(grouped2.keys().cloned())
            .collect();

        for vuln_type in vuln_types {
            let mut old_vulns = grouped1.remove(&vuln_type).unwrap_or_default();
            let mut new_vulns = grouped2.remove(&vuln_type).unwrap_or_default();
            let allow_zero_score_pairing =
                allows_ambiguous_zero_score_pairing(old_vulns.len(), new_vulns.len());

            old_vulns.sort_by_key(vulnerability_sort_key);
            new_vulns.sort_by_key(vulnerability_sort_key);

            let mut candidates = Vec::new();
            for (old_index, old_vuln) in old_vulns.iter().enumerate() {
                for (new_index, new_vuln) in new_vulns.iter().enumerate() {
                    candidates.push(VulnerabilityPairCandidate {
                        score: vulnerability_match_score(old_vuln, new_vuln),
                        old_index,
                        new_index,
                        old_key: vulnerability_sort_key(old_vuln),
                        new_key: vulnerability_sort_key(new_vuln),
                        old: old_vuln,
                        new: new_vuln,
                    });
                }
            }

            candidates.sort_by(|a, b| {
                b.score
                    .cmp(&a.score)
                    .then_with(|| a.old_key.cmp(&b.old_key))
                    .then_with(|| a.new_key.cmp(&b.new_key))
                    .then_with(|| a.old_index.cmp(&b.old_index))
                    .then_with(|| a.new_index.cmp(&b.new_index))
            });

            let mut old_used = vec![false; old_vulns.len()];
            let mut new_used = vec![false; new_vulns.len()];

            for candidate in candidates {
                if old_used[candidate.old_index] || new_used[candidate.new_index] {
                    continue;
                }
                if candidate.score == 0 && !allow_zero_score_pairing {
                    continue;
                }

                old_used[candidate.old_index] = true;
                new_used[candidate.new_index] = true;

                if vulnerability_record_changed(candidate.old, candidate.new) {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Vulnerability,
                        severity: Self::vulnerability_change_severity(candidate.old, candidate.new),
                        description: format!("Vulnerability changed: {}", vuln_type),
                        previous_value: Some(Self::vulnerability_detail(candidate.old)),
                        current_value: Some(Self::vulnerability_detail(candidate.new)),
                        timestamp,
                    });
                }
            }

            for (index, vuln) in old_vulns.iter().enumerate() {
                if !old_used[index] {
                    let severity = Self::vuln_severity_to_change_severity(&vuln.severity);

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Vulnerability,
                        severity,
                        description: format!("Vulnerability resolved: {}", vuln_type),
                        previous_value: Some(Self::vulnerability_detail(vuln)),
                        current_value: Some("resolved".to_string()),
                        timestamp,
                    });
                }
            }

            for (index, vuln) in new_vulns.iter().enumerate() {
                if !new_used[index] {
                    let severity = Self::vuln_severity_to_change_severity(&vuln.severity);

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Vulnerability,
                        severity,
                        description: format!("New vulnerability detected: {}", vuln_type),
                        previous_value: None,
                        current_value: Some(Self::vulnerability_detail(vuln)),
                        timestamp,
                    });
                }
            }
        }

        Ok(changes)
    }

    fn vuln_severity_to_change_severity(severity: &str) -> ChangeSeverity {
        match severity.to_ascii_lowercase().as_str() {
            "critical" => ChangeSeverity::Critical,
            "high" => ChangeSeverity::High,
            "medium" => ChangeSeverity::Medium,
            "low" => ChangeSeverity::Low,
            _ => ChangeSeverity::Info,
        }
    }

    fn vulnerability_change_severity(
        old: &VulnerabilityRecord,
        new: &VulnerabilityRecord,
    ) -> ChangeSeverity {
        std::cmp::max(
            Self::vuln_severity_to_change_severity(&old.severity),
            Self::vuln_severity_to_change_severity(&new.severity),
        )
    }

    fn vulnerability_detail(vuln: &VulnerabilityRecord) -> String {
        let mut details = vec![format!("severity={}", vuln.severity)];

        if let Some(description) = &vuln.description {
            details.push(format!("description={}", description));
        }
        if let Some(cve) = &vuln.cve_id {
            details.push(format!("cve={}", cve));
        }
        if let Some(component) = &vuln.affected_component {
            details.push(format!("component={}", component));
        }

        details.join(", ")
    }
}
