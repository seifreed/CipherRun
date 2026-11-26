// ChangeTracker rating-change detection

use super::*;
use crate::db::analytics::rating_category::rating_category_rank;

impl ChangeTracker {
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

    fn overall_rating_detail(grade: &str, score: Option<i32>) -> String {
        let score = score
            .map(|value| value.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        format!("{grade} ({score})")
    }

    fn rating_change_severity(old: &RatingRecord, new: &RatingRecord) -> ChangeSeverity {
        match new.score.cmp(&old.score) {
            std::cmp::Ordering::Less => ChangeSeverity::High,
            std::cmp::Ordering::Greater => ChangeSeverity::Low,
            // The caller invokes this only when some rating field changed.
            std::cmp::Ordering::Equal => ChangeSeverity::Medium,
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
            rating_category_rank(a)
                .cmp(&rating_category_rank(b))
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
                    .map(|g| Self::overall_rating_detail(&g, scan1.overall_score)),
                current_value: scan2
                    .overall_grade
                    .clone()
                    .map(|g| Self::overall_rating_detail(&g, scan2.overall_score)),
                timestamp,
            });
        }

        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DatabaseConfig;
    use std::path::PathBuf;

    #[tokio::test]
    async fn detect_rating_changes_rejects_scans_without_ids() {
        let db = CipherRunDatabase::new(&DatabaseConfig::sqlite(PathBuf::from(":memory:")))
            .await
            .unwrap();
        let tracker = ChangeTracker::new(Arc::new(db));
        let missing_id = ScanRecord::new("rating-id.test".to_string(), 443);
        let existing_id = ScanRecord {
            scan_id: Some(1),
            ..ScanRecord::new("rating-id.test".to_string(), 443)
        };
        let timestamp = Utc::now();

        let error = tracker
            .detect_rating_changes(&missing_id, &existing_id, timestamp)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Scan 1 missing scan_id"));

        let error = tracker
            .detect_rating_changes(&existing_id, &missing_id, timestamp)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Scan 2 missing scan_id"));

        let changes = tracker
            .detect_rating_changes(&existing_id, &existing_id, timestamp)
            .await
            .unwrap();
        assert!(changes.is_empty());
    }

    #[tokio::test]
    async fn detect_rating_changes_preserves_rating_query_errors() {
        let db = CipherRunDatabase::new(&DatabaseConfig::sqlite(PathBuf::from(":memory:")))
            .await
            .unwrap();
        db.pool
            .execute("DROP TABLE ratings", Vec::new())
            .await
            .unwrap();
        let tracker = ChangeTracker::new(Arc::new(db));
        let old_scan = ScanRecord {
            scan_id: Some(1),
            ..ScanRecord::new("rating-query-error.test".to_string(), 443)
        };
        let new_scan = ScanRecord {
            scan_id: Some(2),
            ..ScanRecord::new("rating-query-error.test".to_string(), 443)
        };

        let error = tracker
            .detect_rating_changes(&old_scan, &new_scan, Utc::now())
            .await
            .expect_err("missing ratings table should fail the comparison");
        assert!(error.to_string().contains("Failed to fetch ratings"));
    }

    #[tokio::test]
    async fn detect_rating_changes_reports_category_and_overall_outcomes() {
        let db = CipherRunDatabase::new(&DatabaseConfig::sqlite(PathBuf::from(":memory:")))
            .await
            .unwrap();
        let DatabasePool::Sqlite(pool) = db.pool() else {
            unreachable!("test database uses SQLite");
        };
        let timestamp = Utc::now();
        let mut scan_ids = Vec::new();
        for (grade, score) in [("A", 95_i32), ("B", 85_i32)] {
            let result = sqlx::query(
                "INSERT INTO scans (target_hostname, target_port, scan_timestamp, overall_grade, overall_score) VALUES (?, ?, ?, ?, ?)",
            )
            .bind("ratings.example")
            .bind(443_i32)
            .bind(timestamp)
            .bind(grade)
            .bind(score)
            .execute(pool)
            .await
            .unwrap();
            scan_ids.push(result.last_insert_rowid());
        }

        for (scan_id, category, score, grade) in [
            (scan_ids[0], "certificate", 90_i32, Some("A")),
            (scan_ids[0], "protocol", 80_i32, Some("B")),
            (scan_ids[0], "key_exchange", 70_i32, Some("C")),
            (scan_ids[0], "cipher", 60_i32, None),
            (scan_ids[1], "certificate", 80_i32, Some("B")),
            (scan_ids[1], "protocol", 90_i32, Some("A")),
            (scan_ids[1], "key_exchange", 70_i32, Some("B")),
            (scan_ids[1], "new_category", 88_i32, Some("A")),
        ] {
            sqlx::query(
                "INSERT INTO ratings (scan_id, category, score, grade) VALUES (?, ?, ?, ?)",
            )
            .bind(scan_id)
            .bind(category)
            .bind(score)
            .bind(grade)
            .execute(pool)
            .await
            .unwrap();
        }

        let mut old_scan = ScanRecord::new("ratings.example".to_string(), 443);
        old_scan.scan_id = Some(scan_ids[0]);
        old_scan.overall_grade = Some("A".to_string());
        old_scan.overall_score = Some(95);
        let mut new_scan = ScanRecord::new("ratings.example".to_string(), 443);
        new_scan.scan_id = Some(scan_ids[1]);
        new_scan.overall_grade = Some("B".to_string());
        new_scan.overall_score = Some(85);

        let tracker = ChangeTracker::new(Arc::new(db));
        let changes = tracker
            .detect_rating_changes(&old_scan, &new_scan, timestamp)
            .await
            .unwrap();

        assert_eq!(changes.len(), 6);
        let change_for = |description: &str| {
            changes
                .iter()
                .find(|change| change.description == description)
                .expect("expected rating change")
        };
        assert_eq!(
            change_for("Rating changed: certificate").severity,
            ChangeSeverity::High
        );
        assert_eq!(
            change_for("Rating changed: protocol").severity,
            ChangeSeverity::Low
        );
        assert_eq!(
            change_for("Rating changed: key_exchange").severity,
            ChangeSeverity::Medium
        );
        assert_eq!(
            change_for("Rating removed: cipher").severity,
            ChangeSeverity::Medium
        );
        assert_eq!(
            change_for("Rating added: new_category").severity,
            ChangeSeverity::Medium
        );
        let overall = change_for("Overall rating changed");
        assert_eq!(overall.severity, ChangeSeverity::High);
        assert_eq!(overall.previous_value.as_deref(), Some("A (95)"));
        assert_eq!(overall.current_value.as_deref(), Some("B (85)"));
    }
}
