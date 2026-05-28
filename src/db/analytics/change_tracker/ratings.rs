// ChangeTracker rating-change detection

use super::*;

impl ChangeTracker {
    fn rating_category_rank(category: &str) -> usize {
        match category {
            "certificate" => 0,
            "protocol" => 1,
            "key_exchange" => 2,
            "cipher" => 3,
            _ => 4,
        }
    }

    fn rating_detail(rating: &RatingRecord) -> String {
        let mut details = vec![
            format!("score={}", rating.score),
            format!("grade={}", rating.grade.as_deref().unwrap_or("N/A")),
        ];

        if let Some(rationale) = &rating.rationale {
            details.push(format!("rationale={}", rationale));
        }

        details.join(", ")
    }

    fn rating_change_severity(old: &RatingRecord, new: &RatingRecord) -> ChangeSeverity {
        match new.score.cmp(&old.score) {
            std::cmp::Ordering::Less => ChangeSeverity::High,
            std::cmp::Ordering::Greater => ChangeSeverity::Low,
            std::cmp::Ordering::Equal => {
                if old.grade != new.grade || old.rationale != new.rationale {
                    ChangeSeverity::Medium
                } else {
                    ChangeSeverity::Info
                }
            }
        }
    }

    pub(super) async fn detect_rating_changes(
        &self,
        scan1: &ScanRecord,
        scan2: &ScanRecord,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let mut changes = Vec::new();

        let scan1_id = scan1
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan 1 missing scan_id".to_string()))?;
        let scan2_id = scan2
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan 2 missing scan_id".to_string()))?;

        let ratings1 = self.get_ratings(scan1_id).await?;
        let ratings2 = self.get_ratings(scan2_id).await?;

        let ratings1_by_category: std::collections::BTreeMap<String, RatingRecord> = ratings1
            .into_iter()
            .map(|rating| (rating.category.clone(), rating))
            .collect();
        let ratings2_by_category: std::collections::BTreeMap<String, RatingRecord> = ratings2
            .into_iter()
            .map(|rating| (rating.category.clone(), rating))
            .collect();

        let mut categories: Vec<String> = ratings1_by_category
            .keys()
            .cloned()
            .chain(ratings2_by_category.keys().cloned())
            .collect();
        categories.sort_by(|a, b| {
            Self::rating_category_rank(a)
                .cmp(&Self::rating_category_rank(b))
                .then_with(|| a.cmp(b))
        });
        categories.dedup();

        for category in categories {
            match (
                ratings1_by_category.get(&category),
                ratings2_by_category.get(&category),
            ) {
                (Some(old), Some(new))
                    if old.score != new.score
                        || old.grade != new.grade
                        || old.rationale != new.rationale =>
                {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Rating,
                        severity: Self::rating_change_severity(old, new),
                        description: format!("Rating changed: {}", category),
                        previous_value: Some(Self::rating_detail(old)),
                        current_value: Some(Self::rating_detail(new)),
                        timestamp,
                    });
                }
                (Some(old), None) => {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Rating,
                        severity: ChangeSeverity::Medium,
                        description: format!("Rating removed: {}", category),
                        previous_value: Some(Self::rating_detail(old)),
                        current_value: None,
                        timestamp,
                    });
                }
                (None, Some(new)) => {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Rating,
                        severity: ChangeSeverity::Medium,
                        description: format!("Rating added: {}", category),
                        previous_value: None,
                        current_value: Some(Self::rating_detail(new)),
                        timestamp,
                    });
                }
                (Some(_), Some(_)) | (None, None) => {}
            }
        }

        if scan1.overall_grade != scan2.overall_grade || scan1.overall_score != scan2.overall_score
        {
            let severity = match (scan1.overall_score, scan2.overall_score) {
                (Some(old), Some(new)) if new < old => ChangeSeverity::High,
                (Some(old), Some(new)) if new > old => ChangeSeverity::Low,
                _ => ChangeSeverity::Medium,
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Rating,
                severity,
                description: "Overall rating changed".to_string(),
                previous_value: scan1
                    .overall_grade
                    .clone()
                    .map(|g| format!("{} ({})", g, scan1.overall_score.unwrap_or(0))),
                current_value: scan2
                    .overall_grade
                    .clone()
                    .map(|g| format!("{} ({})", g, scan2.overall_score.unwrap_or(0))),
                timestamp,
            });
        }

        Ok(changes)
    }
}
