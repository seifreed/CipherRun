// NOTE: These view models are presentation-layer concerns housed in application/
// for convenience. They hold borrowed references to domain types and provide
// rendering-decision logic consumed by the commands/ layer. If a dedicated
// presentation layer is introduced, these should move there.
mod cli_view;
mod post_processing;
mod report;
mod section_views;

// Architecture guard anchors for the split module:
// should_render_post_scan_notices
// should_render_primary_tls_sections
// should_render_primary_tls_view(&self)
// should_render_detailed_results(&self)
// should_render_results_summary_only(&self)
// should_render_results(&self)
// should_render_results_summary(&self)
// should_render_feature_view(&self)
// should_render_fingerprint_view(&self)
// should_render_compliance_section
// should_render_policy_section
// should_render_export_spacing_for(&self, exported: bool)
// pub struct ScanPostView
// compliance_failed(&self)
// policy_failed(&self)
// has_failures(&self)
// should_return_failure_exit(&self)
// should_render_policy_failure_notice(&self)
// should_skip_artifacts(&self)
// should_render_post_processing(&self)
// should_render_artifact_notices(&self)
// should_render_artifact_notices_for(&self, has_artifacts: bool)
// should_render_post_scan_notices_for(&self, has_artifacts: bool)
// should_render_post_scan_export_spacing_for(
// stored_scan_id_for_post_scan_notices(&self, has_artifacts: bool)
// stored_scan_id_for_artifact_notices(&self)
// should_render_post_scan_export_spacing(&self, exported: bool)
// should_handle_artifacts(&self)
// should_export_artifacts(&self)
// should_render_storage_notice_for(&self, stored_scan_id: Option<i64>)
// should_render_storage_notice(&self)
// stored_scan_id_for_notice(&self)
// has_multi_ip_export_data
// should_build_export_plan
// pub struct ScanExportView
// has_exportable_results(&self)
// has_multi_ip_export_data(&self)
// pub struct ScanNoticeView
// should_render_any_notice(&self)
// has_stored_scan(&self)
// pub struct ScanPrimaryTlsView
// pub struct ScanFeatureView
// pub struct ScanFingerprintView

pub use cli_view::ScanCliView;
pub use post_processing::{ScanNoticeView, ScanPostProcessingView, ScanPostView};
pub use report::ScanExecutionReport;
pub use section_views::{ScanExportView, ScanFeatureView, ScanFingerprintView, ScanPrimaryTlsView};
