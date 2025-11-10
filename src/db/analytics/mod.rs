// Analytics Module
// Advanced analytics and reporting for historical scan data

pub mod change_tracker;
pub mod scan_comparator;
pub mod trend_analyzer;
pub mod dashboard_generator;

pub use change_tracker::{ChangeTracker, ChangeEvent, ChangeType, ChangeSeverity};
pub use scan_comparator::{
    ScanComparator, ScanComparison, ProtocolDiff, CipherDiff, CertificateDiff,
    VulnerabilityDiff, RatingDiff, ComparisonSummary
};
pub use trend_analyzer::{
    TrendAnalyzer, RatingTrend, VulnerabilityTrend, ProtocolTrend,
    TrendDirection, CipherStrengthTrend
};
pub use dashboard_generator::{
    DashboardGenerator, DashboardData, TimeSeriesPoint, DistributionPoint,
    IssueItem, DashboardSummary
};
