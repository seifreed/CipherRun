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

#[cfg(test)]
mod tests {
    use super::ScanExecutionReport;
    use crate::application::{ComplianceReport, ComplianceStatus, ScanResults};
    use crate::compliance::ComplianceFramework;

    #[test]
    fn absent_optional_results_do_not_fail_the_scan() {
        let report = ScanExecutionReport::new(ScanResults::default(), None, None, None);

        assert!(!report.has_compliance_report());
        assert!(!report.has_policy_result());
        assert!(!report.has_stored_scan());
        assert!(!report.compliance_failed());
        assert!(!report.policy_failed(false));
        assert!(!report.should_fail_exit(false));
        assert!(!report.should_fail_exit(true));
        assert!(!report.post_processing_view(true).should_fail_exit());
    }

    #[test]
    fn passing_compliance_report_does_not_fail_the_scan() {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test".to_string(),
            version: "1".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        };
        let compliance = ComplianceReport::new(&framework, "example.com:443".to_string());
        assert_eq!(compliance.overall_status, ComplianceStatus::Pass);

        let report = ScanExecutionReport::new(ScanResults::default(), Some(compliance), None, None);
        assert!(!report.compliance_failed());
        assert!(!report.should_fail_exit(false));
    }
}
