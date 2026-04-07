use crate::application::scan_execution::cli_view::ScanCliView;
use crate::application::scan_execution::post_processing::ScanPostProcessingView;
use crate::application::{ComplianceReport, ComplianceStatus, PolicyResult, ScanResults};

pub struct ScanExecutionReport {
    scan_results: ScanResults,
    compliance_report: Option<ComplianceReport>,
    policy_result: Option<PolicyResult>,
    stored_scan_id: Option<i64>,
}

impl ScanExecutionReport {
    pub fn new(
        scan_results: ScanResults,
        compliance_report: Option<ComplianceReport>,
        policy_result: Option<PolicyResult>,
        stored_scan_id: Option<i64>,
    ) -> Self {
        Self {
            scan_results,
            compliance_report,
            policy_result,
            stored_scan_id,
        }
    }

    pub fn results(&self) -> &ScanResults {
        &self.scan_results
    }

    pub fn compliance_report(&self) -> Option<&ComplianceReport> {
        self.compliance_report.as_ref()
    }

    pub fn policy_result(&self) -> Option<&PolicyResult> {
        self.policy_result.as_ref()
    }

    pub fn stored_scan_id(&self) -> Option<i64> {
        self.stored_scan_id
    }

    pub fn has_stored_scan(&self) -> bool {
        self.stored_scan_id.is_some()
    }

    pub fn has_compliance_report(&self) -> bool {
        self.compliance_report.is_some()
    }

    pub fn has_policy_result(&self) -> bool {
        self.policy_result.is_some()
    }

    pub fn compliance_failed(&self) -> bool {
        self.compliance_report
            .as_ref()
            .is_some_and(|report| report.overall_status == ComplianceStatus::Fail)
    }

    pub fn policy_failed(&self, enforce: bool) -> bool {
        enforce
            && self
                .policy_result
                .as_ref()
                .is_some_and(PolicyResult::has_violations)
    }

    pub fn should_fail_exit(&self, enforce_policy: bool) -> bool {
        self.compliance_failed() || self.policy_failed(enforce_policy)
    }

    pub fn post_processing_view(&self, enforce_policy: bool) -> ScanPostProcessingView<'_> {
        ScanPostProcessingView {
            compliance_report: self.compliance_report(),
            policy_result: self.policy_result(),
            stored_scan_id: self.stored_scan_id(),
            should_fail_exit: self.should_fail_exit(enforce_policy),
        }
    }

    pub fn cli_view(&self, enforce_policy: bool) -> ScanCliView<'_> {
        ScanCliView {
            results: self.results(),
            post_processing: self.post_processing_view(enforce_policy),
        }
    }
}
