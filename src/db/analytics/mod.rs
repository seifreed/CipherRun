// Analytics Module
// Advanced analytics and reporting for historical scan data

pub mod change_tracker;
pub mod cipher_trend;
pub mod dashboard_generator;
pub mod protocol_trend;
pub mod rating_trend;
pub mod scan_comparator;
pub mod trend_analyzer;
pub mod vulnerability_trend;

pub use change_tracker::{ChangeEvent, ChangeSeverity, ChangeTracker, ChangeType};
pub use dashboard_generator::{
    DashboardData, DashboardGenerator, DashboardSummary, DistributionPoint, IssueItem,
    TimeSeriesPoint,
};
pub use scan_comparator::{
    CertificateDiff, CipherDiff, ComparisonSummary, ProtocolDiff, RatingDiff, ScanComparator,
    ScanComparison, VulnerabilityDiff,
};
pub use trend_analyzer::{
    CipherStrengthTrend, ProtocolTrend, RatingTrend, TrendAnalyzer, TrendDirection,
    VulnerabilityTrend,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_reexports_basic() {
        let severity = ChangeSeverity::High;
        assert_eq!(format!("{:?}", severity), "High");

        let direction = TrendDirection::Improving;
        assert_eq!(direction, TrendDirection::Improving);
    }
}
