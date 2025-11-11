// Analytics Module
// Advanced analytics and reporting for historical scan data

pub mod change_tracker;
pub mod dashboard_generator;
pub mod scan_comparator;
pub mod trend_analyzer;

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
