// Rating comparison and summary generation methods for ScanComparator

use super::{
    CertificateDiff, CipherDiff, ComparisonSummary, ComponentRatingDiff, ProtocolDiff, RatingDiff,
    ScanComparator, VulnerabilityDiff,
};
use crate::db::analytics::rating_category::rating_category_rank;
use crate::db::connection::DatabasePool;
use crate::db::{RatingRecord, ScanRecord};
use std::collections::BTreeMap;

impl ScanComparator {
    pub(crate) async fn compare_ratings(
        &self,
        scan_1: &ScanRecord,
        scan_2: &ScanRecord,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<RatingDiff> {
        let overall_changed = scan_1.overall_grade != scan_2.overall_grade
            || scan_1.overall_score != scan_2.overall_score;

        let ratings1 = self.get_ratings(scan_id_1).await?;
        let ratings2 = self.get_ratings(scan_id_2).await?;

        let mut ratings1_by_category: BTreeMap<String, &RatingRecord> = BTreeMap::new();
        for rating in &ratings1 {
            ratings1_by_category
                .entry(rating.category.clone())
                .or_insert(rating);
        }

        let mut ratings2_by_category: BTreeMap<String, &RatingRecord> = BTreeMap::new();
        for rating in &ratings2 {
            ratings2_by_category
                .entry(rating.category.clone())
                .or_insert(rating);
        }

        let mut component_diffs = Vec::new();

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
            let rating1 = ratings1_by_category.get(&category);
            let rating2 = ratings2_by_category.get(&category);

            let score1 = rating1.map(|r| r.score);
            let score2 = rating2.map(|r| r.score);
            let grade1 = rating1.and_then(|r| r.grade.clone());
            let grade2 = rating2.and_then(|r| r.grade.clone());
            let rationale1 = rating1.and_then(|r| r.rationale.clone());
            let rationale2 = rating2.and_then(|r| r.rationale.clone());

            let changed = score1 != score2 || grade1 != grade2 || rationale1 != rationale2;

            component_diffs.push(ComponentRatingDiff {
                category,
                scan_1_score: score1,
                scan_1_grade: grade1,
                scan_1_rationale: rationale1,
                scan_2_score: score2,
                scan_2_grade: grade2,
                scan_2_rationale: rationale2,
                changed,
            });
        }

        Ok(RatingDiff {
            overall_changed,
            scan_1_grade: scan_1.overall_grade.clone(), // Necessary: Option<String> for return
            scan_1_score: scan_1.overall_score,
            scan_2_grade: scan_2.overall_grade.clone(), // Necessary: Option<String> for return
            scan_2_score: scan_2.overall_score,
            component_diffs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generate_summary(
        &self,
        scan_1: &ScanRecord,
        scan_2: &ScanRecord,
        protocol_diff: &ProtocolDiff,
        cipher_diff: &CipherDiff,
        certificate_diff: &CertificateDiff,
        vulnerability_diff: &VulnerabilityDiff,
        rating_diff: &RatingDiff,
    ) -> ComparisonSummary {
        let protocol_changes = protocol_diff.added.len()
            + protocol_diff.removed.len()
            + if protocol_diff.preferred_change.is_some() {
                1
            } else {
                0
            };
        let cipher_changes =
            cipher_diff.added.len() + cipher_diff.removed.len() + cipher_diff.changed.len();
        let certificate_changes = if certificate_diff.fingerprint_changed {
            1
        } else {
            0
        };
        let vulnerability_changes = vulnerability_diff.new.len()
            + vulnerability_diff.resolved.len()
            + vulnerability_diff.changed.len();
        let rating_changes = if rating_diff.overall_changed { 1 } else { 0 }
            + rating_diff
                .component_diffs
                .iter()
                .filter(|d| d.changed)
                .count();

        let total_changes = protocol_changes
            + cipher_changes
            + certificate_changes
            + vulnerability_changes
            + rating_changes;

        let time_between_scans = (scan_2.scan_timestamp - scan_1.scan_timestamp).num_seconds();

        ComparisonSummary {
            total_changes,
            protocol_changes,
            cipher_changes,
            certificate_changes,
            vulnerability_changes,
            rating_changes,
            time_between_scans,
        }
    }

    async fn get_ratings(&self, scan_id: i64) -> crate::Result<Vec<RatingRecord>> {
        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let ratings = sqlx::query_as::<_, RatingRecord>(
                    "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = $1 ORDER BY category ASC, rating_id ASC"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ratings: {}", e)))?;
                Ok(ratings)
            }
            DatabasePool::Sqlite(pool) => {
                let ratings = sqlx::query_as::<_, RatingRecord>(
                    "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = ? ORDER BY category ASC, rating_id ASC"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ratings: {}", e)))?;
                Ok(ratings)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::CipherRunDatabase;
    use crate::db::connection::DatabasePool;
    use std::sync::Arc;

    #[cfg(feature = "db-postgres")]
    #[tokio::test]
    async fn compare_ratings_reads_postgres_changes_and_preserves_query_errors() {
        compare_ratings_postgres_with_url(std::env::var("CIPHERRUN_TEST_POSTGRES_URL").ok()).await;
    }

    #[cfg(feature = "db-postgres")]
    #[tokio::test]
    async fn compare_ratings_postgres_test_skips_without_configuration() {
        compare_ratings_postgres_with_url(None).await;
    }

    #[cfg(feature = "db-postgres")]
    async fn compare_ratings_postgres_with_url(url: Option<String>) {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Some(url) = url else {
            return;
        };
        let admin = PgPoolOptions::new()
            .connect_with(PgConnectOptions::from_str(&url).expect("test URL should be valid"))
            .await
            .expect("test PostgreSQL should accept connections");
        let schema = format!("cipherrun_rating_compare_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("test schema should be created");

        let options = PgConnectOptions::from_str(&url)
            .expect("test URL should be valid")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .connect_with(options)
            .await
            .expect("test PostgreSQL schema should accept connections");
        sqlx::query(
            "CREATE TABLE ratings (
                rating_id BIGSERIAL PRIMARY KEY,
                scan_id BIGINT NOT NULL,
                category TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT,
                rationale TEXT
            )",
        )
        .execute(&pool)
        .await
        .expect("ratings table should be created");
        for (scan_id, category, score, grade, rationale) in [
            (1_i64, "certificate", 95_i32, Some("A"), Some("old")),
            (1, "protocol", 80, Some("B"), None),
            (2, "certificate", 90, Some("B"), Some("updated")),
            (2, "cipher", 75, Some("C"), None),
        ] {
            sqlx::query(
                "INSERT INTO ratings (scan_id, category, score, grade, rationale) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(scan_id)
            .bind(category)
            .bind(score)
            .bind(grade)
            .bind(rationale)
            .execute(&pool)
            .await
            .expect("rating should be inserted");
        }

        let database = Arc::new(CipherRunDatabase::from_pool(DatabasePool::Postgres(
            pool.clone(),
        )));
        let comparator = ScanComparator::new(database);
        let mut scan_1 = ScanRecord::new("ratings.example".to_string(), 443);
        scan_1.scan_id = Some(1);
        scan_1.overall_grade = Some("A".to_string());
        scan_1.overall_score = Some(95);
        let mut scan_2 = ScanRecord::new("ratings.example".to_string(), 443);
        scan_2.scan_id = Some(2);
        scan_2.overall_grade = Some("B".to_string());
        scan_2.overall_score = Some(85);

        let diff = comparator
            .compare_ratings(&scan_1, &scan_2, 1, 2)
            .await
            .expect("PostgreSQL ratings should compare");
        assert!(diff.overall_changed);
        assert_eq!(diff.component_diffs.len(), 3);
        assert!(
            diff.component_diffs
                .iter()
                .all(|component| component.changed)
        );
        let certificate = diff
            .component_diffs
            .iter()
            .find(|component| component.category == "certificate")
            .expect("certificate rating should be present");
        assert_eq!(certificate.scan_1_rationale.as_deref(), Some("old"));
        assert_eq!(certificate.scan_2_rationale.as_deref(), Some("updated"));

        sqlx::query("DROP TABLE ratings")
            .execute(&pool)
            .await
            .expect("test should remove the ratings table");
        let error = comparator
            .compare_ratings(&scan_1, &scan_2, 1, 2)
            .await
            .expect_err("a missing PostgreSQL ratings table should fail comparison");
        assert!(error.to_string().contains("Failed to fetch ratings"));

        drop(comparator);
        drop(pool);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("test schema should be removed");
    }

    #[tokio::test]
    async fn compare_ratings_preserves_sqlite_query_errors() {
        use crate::db::DatabaseConfig;
        use std::path::PathBuf;

        let database = CipherRunDatabase::new(&DatabaseConfig::sqlite(PathBuf::from(":memory:")))
            .await
            .expect("in-memory SQLite database should initialize");
        database
            .pool()
            .execute("DROP TABLE ratings", Vec::new())
            .await
            .expect("test should remove the ratings table");

        let scan_1 = ScanRecord::new("ratings.example".to_string(), 443);
        let scan_2 = ScanRecord::new("ratings.example".to_string(), 443);
        let error = ScanComparator::new(Arc::new(database))
            .compare_ratings(&scan_1, &scan_2, 1, 2)
            .await
            .expect_err("a missing SQLite ratings table should fail comparison");

        assert!(error.to_string().contains("Failed to fetch ratings"));
    }
}
