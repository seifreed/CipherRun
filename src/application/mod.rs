pub mod assessment;
pub mod certificate_filters;
pub mod certificate_inventory;
pub mod output_presentation;
pub mod parsed_input;
pub mod persistence;
pub mod ports;
pub mod scan_execution;
pub mod scan_history;
pub mod scan_request;
pub mod use_cases;

pub use assessment::ScanAssessment;
pub use certificate_filters::CertificateFilters;
pub use certificate_inventory::{
    CertificateInventoryPage, CertificateInventoryQuery, CertificateInventoryRecord,
    CertificateInventorySort,
};
pub use output_presentation::OutputPresentationMode;
pub use parsed_input::{CompareScanIds, HostPortDaysInput, HostPortInput};
pub use persistence::PersistedScan;
pub use ports::{
    CertificateInventoryPort, ComplianceEvaluatorPort, ComplianceFrameworkSource,
    PolicyEvaluatorPort, PolicySource, ScanHistoryPort, ScanResultsStore, ScanResultsStoreFactory,
    ScannerPort,
};
pub use scan_execution::{
    ScanCliView, ScanExecutionReport, ScanExportView, ScanFeatureView, ScanFingerprintView,
    ScanNoticeView, ScanPostProcessingView, ScanPostView, ScanPrimaryTlsView,
};
pub use scan_history::{ScanHistoryEntry, ScanHistoryQuery};
pub use scan_request::ScanRequest;

// Domain types re-exported from infrastructure modules
pub use crate::compliance::{ComplianceReport, ComplianceStatus};
pub use crate::policy::PolicyResult;
pub use crate::scanner::ScanResults;
