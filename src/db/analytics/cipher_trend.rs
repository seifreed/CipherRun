// Cipher Strength Trend Analysis
// Analyzes cipher suite strength distribution over time

use super::cipher_strength::cipher_strength_category;
use super::trend_analyzer::{CipherStrengthData, TrendAnalyzer};

impl TrendAnalyzer {
    /// Analyze cipher strength trend over time
    pub async fn analyze_cipher_strength_trend(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<super::trend_analyzer::CipherStrengthTrend> {
        let scans = self.get_scans_in_range(hostname, port, days).await?;

        if scans.is_empty() {
            return Err(crate::TlsError::DatabaseError(
                "No scans found in the specified time range".to_string(),
            ));
        }

        let mut data_points = Vec::new();
        let mut weak_counts = Vec::new();
        let mut strong_counts = Vec::new();

        for scan in &scans {
            if let Some(scan_id) = scan.scan_id {
                let ciphers = self.get_ciphers(scan_id).await?;

                let weak = ciphers
                    .iter()
                    .filter(|c| cipher_strength_category(&c.strength) == "weak")
                    .count();
                let medium = ciphers
                    .iter()
                    .filter(|c| cipher_strength_category(&c.strength) == "medium")
                    .count();
                let strong = ciphers
                    .iter()
                    .filter(|c| cipher_strength_category(&c.strength) == "strong")
                    .count();

                weak_counts.push(weak);
                strong_counts.push(strong);

                data_points.push((
                    scan.scan_timestamp,
                    CipherStrengthData {
                        weak,
                        medium,
                        strong,
                    },
                ));
            }
        }

        let weak_trend = Self::determine_usize_trend_direction(
            &data_points
                .iter()
                .map(|(ts, data)| (*ts, data.weak))
                .collect::<Vec<_>>(),
        );

        // Strong ciphers: more is better, so an increasing count is improving.
        let strong_trend = Self::determine_usize_trend_direction_higher_is_better(
            &data_points
                .iter()
                .map(|(ts, data)| (*ts, data.strong))
                .collect::<Vec<_>>(),
        );

        Ok(super::trend_analyzer::CipherStrengthTrend {
            data_points,
            weak_count_trend: weak_trend,
            strong_count_trend: strong_trend,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{insert_cipher, insert_scan, setup_db};
    use super::super::trend_analyzer::TrendAnalyzer;
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn test_cipher_strength_trend_analysis() {
        let db = setup_db("cipher-trend").await;
        let hostname = "example.com";
        let port = 443;

        let scan1 = insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(2),
            Some("A"),
            Some(95),
        )
        .await;
        let scan2 = insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(1),
            Some("B"),
            Some(80),
        )
        .await;

        insert_cipher(&db, scan1, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "strong").await;
        insert_cipher(&db, scan2, "TLS 1.2", "AES128-SHA", "weak").await;

        let analyzer = TrendAnalyzer::new(db.clone());

        let cipher = analyzer
            .analyze_cipher_strength_trend(hostname, port, 30)
            .await
            .expect("cipher trend should succeed");
        assert_eq!(cipher.data_points.len(), 2);
    }

    #[tokio::test]
    async fn test_cipher_strength_trend_counts_low_strength_as_weak() {
        let db = setup_db("cipher-trend").await;
        let hostname = "low-cipher.example.com";
        let port = 443;

        let scan = insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(1),
            Some("C"),
            Some(55),
        )
        .await;

        insert_cipher(&db, scan, "TLS 1.2", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "low").await;

        let analyzer = TrendAnalyzer::new(db.clone());

        let cipher = analyzer
            .analyze_cipher_strength_trend(hostname, port, 30)
            .await
            .expect("cipher trend should succeed");
        assert_eq!(cipher.data_points.len(), 1);
        assert_eq!(cipher.data_points[0].1.weak, 1);
        assert_eq!(cipher.data_points[0].1.medium, 0);
        assert_eq!(cipher.data_points[0].1.strong, 0);
    }
}
