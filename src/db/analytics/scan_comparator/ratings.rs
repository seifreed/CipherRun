// Rating comparison and summary generation methods for ScanComparator

use super::{
    CertificateDiff, CipherDiff, ComparisonSummary, ComponentRatingDiff, ProtocolDiff, RatingDiff,
    ScanComparator, VulnerabilityDiff,
};
use crate::db::connection::DatabasePool;
use crate::db::{RatingRecord, ScanRecord};

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

        let mut component_diffs = Vec::new();

        let categories = vec!["certificate", "protocol", "key_exchange", "cipher"];
        for category in categories {
            let score1 = ratings1
                .iter()
                .find(|r| r.category == category)
                .map(|r| r.score);
            let score2 = ratings2
                .iter()
                .find(|r| r.category == category)
                .map(|r| r.score);

            component_diffs.push(ComponentRatingDiff {
                category: category.to_string(),
                scan_1_score: score1,
                scan_2_score: score2,
                changed: score1 != score2,
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
                    "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ratings: {}", e)))?;
                Ok(ratings)
            }
            DatabasePool::Sqlite(pool) => {
                let ratings = sqlx::query_as::<_, RatingRecord>(
                    "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = ?"
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
