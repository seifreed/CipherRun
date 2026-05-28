// ChangeTracker protocol-change detection

use super::*;

impl ChangeTracker {
    pub(super) async fn detect_protocol_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let protocols1 = self.get_protocols(scan_id_1).await?;
        let protocols2 = self.get_protocols(scan_id_2).await?;

        let mut changes = Vec::new();

        let protocol_names1: BTreeMap<String, String> = protocols1
            .iter()
            .filter(|p| p.enabled)
            .map(|p| (protocol_identity(&p.protocol_name), p.protocol_name.clone()))
            .collect();

        let protocol_names2: BTreeMap<String, String> = protocols2
            .iter()
            .filter(|p| p.enabled)
            .map(|p| (protocol_identity(&p.protocol_name), p.protocol_name.clone()))
            .collect();

        let set1: HashSet<String> = protocol_names1.keys().cloned().collect();
        let set2: HashSet<String> = protocol_names2.keys().cloned().collect();
        let diffs = detect_set_differences(&set1, &set2);

        for proto_key in &diffs.removed {
            let proto = protocol_names1
                .get(proto_key)
                .map(String::as_str)
                .unwrap_or(proto_key.as_str());
            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity: ChangeSeverity::Medium,
                description: format!("Protocol removed: {}", proto),
                previous_value: Some("enabled".to_string()),
                current_value: Some("disabled".to_string()),
                timestamp,
            });
        }

        for proto_key in &diffs.added {
            let proto = protocol_names2
                .get(proto_key)
                .map(String::as_str)
                .unwrap_or(proto_key.as_str());
            let severity = if is_ssl_protocol(proto) {
                ChangeSeverity::High
            } else if is_tls_version(proto, "1.3") {
                ChangeSeverity::Info
            } else {
                ChangeSeverity::Low
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity,
                description: format!("Protocol added: {}", proto),
                previous_value: Some("disabled".to_string()),
                current_value: Some("enabled".to_string()),
                timestamp,
            });
        }

        // Preferred protocol changes
        let pref1 = protocols1
            .iter()
            .find(|p| p.preferred)
            .map(|p| p.protocol_name.as_str());
        let pref2 = protocols2
            .iter()
            .find(|p| p.preferred)
            .map(|p| p.protocol_name.as_str());

        let pref1_normalized = pref1.map(protocol_identity);
        let pref2_normalized = pref2.map(protocol_identity);

        if pref1_normalized != pref2_normalized {
            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity: ChangeSeverity::Low,
                description: "Preferred protocol changed".to_string(),
                previous_value: pref1.map(str::to_string),
                current_value: pref2.map(str::to_string),
                timestamp,
            });
        }

        Ok(changes)
    }
}
