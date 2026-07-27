use super::*;
use crate::db::analytics::test_support::{
    insert_cipher, insert_protocol, insert_scan, insert_vulnerability, setup_db,
};
use crate::db::{BindValue, CipherRunDatabase};
use chrono::{Duration, Utc};
use std::collections::BTreeMap;

#[test]
fn test_cutoff_days_ago_rejects_invalid_days() {
    assert!(cutoff_days_ago(0).is_err());
    assert!(cutoff_days_ago(-1).is_err());
    assert!(cutoff_days_ago(i64::MAX).is_err());
}

#[test]
fn test_calculate_mean() {
    let values = vec![80, 85, 90, 95, 100];
    let mean = TrendAnalyzer::calculate_mean(&values);
    assert_eq!(mean, 90.0);
}

#[test]
fn test_calculate_median_odd() {
    let mut values = vec![80, 85, 90, 95, 100];
    let median = TrendAnalyzer::calculate_median(&mut values);
    assert_eq!(median, 90);
}

#[test]
fn test_calculate_median_even() {
    let mut values = vec![80, 85, 90, 95];
    let median = TrendAnalyzer::calculate_median(&mut values);
    assert_eq!(median, 87);
}

#[test]
fn test_calculate_usize_median_even() {
    let mut values = vec![1usize, 4usize];
    let median = TrendAnalyzer::calculate_usize_median(&mut values);
    assert_eq!(median, 2);
}

#[test]
fn test_vulnerability_trend_serializes_severity_distribution_deterministically() {
    let mut first_distribution = BTreeMap::new();
    first_distribution.insert("medium".to_string(), 2);
    first_distribution.insert("high".to_string(), 1);

    let mut second_distribution = BTreeMap::new();
    second_distribution.insert("high".to_string(), 1);
    second_distribution.insert("medium".to_string(), 2);

    let first = VulnerabilityTrend {
        data_points: vec![],
        mean: 0.0,
        median: 0,
        severity_distribution: first_distribution,
        direction: TrendDirection::Stable,
    };
    let second = VulnerabilityTrend {
        data_points: vec![],
        mean: 0.0,
        median: 0,
        severity_distribution: second_distribution,
        direction: TrendDirection::Stable,
    };

    let first_json = serde_json::to_string(&first).expect("serialization should succeed");
    let second_json = serde_json::to_string(&second).expect("serialization should succeed");

    assert_eq!(first_json, second_json);
    assert!(
        first_json.find("\"high\":1").expect("high severity")
            < first_json.find("\"medium\":2").expect("medium severity")
    );
}

#[test]
fn test_calculate_std_dev() {
    let values = vec![80, 85, 90, 95, 100];
    let mean = TrendAnalyzer::calculate_mean(&values);
    let std_dev = TrendAnalyzer::calculate_std_dev(&values, mean);
    assert!(std_dev > 7.0 && std_dev < 8.0);
}

#[test]
fn test_trend_direction() {
    let improving = vec![
        (Utc::now(), 70),
        (Utc::now(), 75),
        (Utc::now(), 80),
        (Utc::now(), 85),
    ];
    assert_eq!(
        TrendAnalyzer::determine_trend_direction(&improving),
        TrendDirection::Improving
    );

    let degrading = vec![
        (Utc::now(), 90),
        (Utc::now(), 85),
        (Utc::now(), 80),
        (Utc::now(), 75),
    ];
    assert_eq!(
        TrendAnalyzer::determine_trend_direction(&degrading),
        TrendDirection::Degrading
    );
}

#[test]
fn test_trend_direction_stable_and_usize() {
    let stable = vec![(Utc::now(), 80), (Utc::now(), 81), (Utc::now(), 79)];
    assert_eq!(
        TrendAnalyzer::determine_trend_direction(&stable),
        TrendDirection::Stable
    );

    let improving = vec![(Utc::now(), 10usize), (Utc::now(), 5usize)];
    assert_eq!(
        TrendAnalyzer::determine_usize_trend_direction(&improving),
        TrendDirection::Improving
    );

    let degrading = vec![(Utc::now(), 1usize), (Utc::now(), 10usize)];
    assert_eq!(
        TrendAnalyzer::determine_usize_trend_direction(&degrading),
        TrendDirection::Degrading
    );
}

#[test]
fn test_strong_cipher_trend_direction_higher_is_better() {
    let base = Utc::now();

    // A growing strong-cipher count is an improvement.
    let increasing = vec![
        (base, 2usize),
        (base + Duration::minutes(1), 5usize),
        (base + Duration::minutes(2), 9usize),
    ];
    assert_eq!(
        TrendAnalyzer::determine_usize_trend_direction_higher_is_better(&increasing),
        TrendDirection::Improving
    );

    // A shrinking strong-cipher count is a regression.
    let decreasing = vec![
        (base, 9usize),
        (base + Duration::minutes(1), 5usize),
        (base + Duration::minutes(2), 2usize),
    ];
    assert_eq!(
        TrendAnalyzer::determine_usize_trend_direction_higher_is_better(&decreasing),
        TrendDirection::Degrading
    );
}

#[test]
fn test_forecast_linear() {
    let points = vec![(Utc::now(), 60), (Utc::now(), 70), (Utc::now(), 80)];
    let forecast = TrendAnalyzer::forecast_linear(&points).unwrap();
    assert!(forecast >= 80);
}

#[test]
fn test_trend_functions_are_order_independent() {
    let base = Utc::now();
    let rating_points_desc = vec![
        (base + Duration::minutes(2), 80),
        (base + Duration::minutes(1), 70),
        (base, 60),
    ];
    assert_eq!(
        TrendAnalyzer::determine_trend_direction(&rating_points_desc),
        TrendDirection::Improving
    );
    assert_eq!(
        TrendAnalyzer::forecast_linear(&rating_points_desc),
        Some(90)
    );

    let vuln_points_desc = vec![
        (base + Duration::minutes(2), 15usize),
        (base + Duration::minutes(1), 10usize),
        (base, 5usize),
    ];
    assert_eq!(
        TrendAnalyzer::determine_usize_trend_direction(&vuln_points_desc),
        TrendDirection::Degrading
    );
}

#[tokio::test]
async fn test_trend_analyzer_with_database_data() {
    let db = setup_db("trend").await;
    let hostname = "2001:db8::1";
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

    insert_protocol(&db, scan1, "TLS 1.3", true, true).await;
    insert_protocol(&db, scan1, "TLS 1.2", true, false).await;
    insert_protocol(&db, scan2, "TLS 1.2", true, true).await;
    insert_protocol(&db, scan2, "SSLv3", true, false).await;

    insert_cipher(&db, scan1, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "strong").await;
    insert_cipher(&db, scan2, "TLS 1.2", "AES128-SHA", "weak").await;

    insert_vulnerability(&db, scan1, "ROBOT", "high").await;
    insert_vulnerability(&db, scan2, "SWEET32", "medium").await;
    insert_vulnerability(&db, scan2, "LOGJAM", "low").await;

    let analyzer = TrendAnalyzer::new(db.clone());

    let rating = analyzer
        .analyze_rating_trend(hostname, port, 30)
        .await
        .expect("rating trend should succeed");
    assert_eq!(rating.data_points.len(), 2);
    assert!(rating.mean > 0.0);

    let vuln = analyzer
        .analyze_vulnerability_trend(hostname, port, 30)
        .await
        .expect("vulnerability trend should succeed");
    assert_eq!(vuln.data_points.len(), 2);
    // One vuln of each severity was inserted across the two scans; the
    // distribution must preserve those counts, not truncate them to zero.
    assert_eq!(vuln.severity_distribution.get("high"), Some(&1));
    assert_eq!(vuln.severity_distribution.get("medium"), Some(&1));
    assert_eq!(vuln.severity_distribution.get("low"), Some(&1));

    let protocol = analyzer
        .analyze_protocol_trend(hostname, port, 30)
        .await
        .expect("protocol trend should succeed");
    assert!(protocol.summary.contains("TLS 1.3 adoption"));

    let cipher = analyzer
        .analyze_cipher_strength_trend(hostname, port, 30)
        .await
        .expect("cipher trend should succeed");
    assert_eq!(cipher.data_points.len(), 2);

    let report = analyzer
        .generate_trend_report(hostname, port, 30)
        .await
        .expect("trend report should succeed");
    assert!(report.contains("TREND ANALYSIS REPORT"));
    assert!(report.contains("RATING TREND"));
    assert!(report.contains("Target: [2001:db8::1]:443"));

    let high_pos = report
        .find("  high: ")
        .expect("high severity line should exist");
    let medium_pos = report
        .find("  medium: ")
        .expect("medium severity line should exist");
    let low_pos = report
        .find("  low: ")
        .expect("low severity line should exist");
    assert!(high_pos < medium_pos);
    assert!(medium_pos < low_pos);
}
