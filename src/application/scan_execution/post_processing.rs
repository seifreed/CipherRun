use crate::application::{ComplianceReport, ComplianceStatus, PolicyResult};

pub struct ScanPostProcessingView<'a> {
    pub(crate) compliance_report: Option<&'a ComplianceReport>,
    pub(crate) policy_result: Option<&'a PolicyResult>,
    pub(crate) stored_scan_id: Option<i64>,
    pub(crate) should_fail_exit: bool,
}

impl<'a> ScanPostProcessingView<'a> {
    pub fn should_render_compliance_section(&self) -> bool {
        self.has_compliance_report()
    }

    pub fn has_compliance_report(&self) -> bool {
        self.compliance_report.is_some()
    }

    pub fn compliance_report(&self) -> Option<&'a ComplianceReport> {
        self.compliance_report
    }

    pub fn should_render_policy_section(&self) -> bool {
        self.has_policy_result()
    }

    pub fn has_policy_result(&self) -> bool {
        self.policy_result.is_some()
    }

    pub fn policy_result(&self) -> Option<&'a PolicyResult> {
        self.policy_result
    }

    pub fn stored_scan_id(&self) -> Option<i64> {
        self.stored_scan_id
    }

    pub fn has_stored_scan(&self) -> bool {
        self.stored_scan_id.is_some()
    }

    pub fn should_fail_exit(&self) -> bool {
        self.should_fail_exit
    }

    pub fn should_render_any_section(&self) -> bool {
        self.has_compliance_report() || self.has_policy_result()
    }

    pub fn should_render_storage_notice(&self) -> bool {
        self.has_stored_scan()
    }
}

pub struct ScanPostView<'a> {
    pub(crate) post_processing: &'a ScanPostProcessingView<'a>,
}

impl<'a> ScanPostView<'a> {
    pub fn should_render(&self) -> bool {
        self.post_processing.should_render_any_section()
    }

    pub fn compliance_failed(&self) -> bool {
        self.compliance_report()
            .is_some_and(|report| report.overall_status == ComplianceStatus::Fail)
    }

    pub fn policy_failed(&self) -> bool {
        self.policy_result()
            .is_some_and(PolicyResult::has_violations)
    }

    pub fn has_failures(&self) -> bool {
        self.compliance_failed() || self.policy_failed()
    }

    pub fn should_fail_exit(&self) -> bool {
        self.post_processing.should_fail_exit()
    }

    pub fn should_return_failure_exit(&self) -> bool {
        self.should_fail_exit() && self.has_failures()
    }

    pub fn should_render_policy_failure_notice(&self) -> bool {
        self.should_return_failure_exit() && self.policy_failed()
    }

    pub fn should_render_compliance_section(&self) -> bool {
        self.post_processing.should_render_compliance_section()
    }

    pub fn compliance_report(&self) -> Option<&'a ComplianceReport> {
        self.post_processing.compliance_report()
    }

    pub fn should_render_policy_section(&self) -> bool {
        self.post_processing.should_render_policy_section()
    }

    pub fn policy_result(&self) -> Option<&'a PolicyResult> {
        self.post_processing.policy_result()
    }
}

pub struct ScanNoticeView {
    pub(crate) stored_scan_id: Option<i64>,
}

impl ScanNoticeView {
    pub fn has_stored_scan(&self) -> bool {
        self.stored_scan_id.is_some()
    }

    pub fn should_render_any_notice(&self) -> bool {
        self.has_stored_scan()
    }

    pub fn stored_scan_id(&self) -> Option<i64> {
        self.stored_scan_id
    }

    pub fn stored_scan_id_for_notice(&self) -> Option<i64> {
        self.should_render_storage_notice()
            .then_some(self.stored_scan_id)
            .flatten()
    }

    pub fn should_render_storage_notice_for(&self, stored_scan_id: Option<i64>) -> bool {
        self.should_render_storage_notice() && stored_scan_id.is_some()
    }

    pub fn should_render_export_spacing_for(&self, exported: bool) -> bool {
        self.should_render_any_notice() && exported
    }

    pub fn should_render_storage_notice(&self) -> bool {
        self.should_render_any_notice()
    }
}
