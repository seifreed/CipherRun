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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::ComplianceFramework;
    use crate::policy::violation::PolicyViolation;
    use crate::policy::{PolicyAction, PolicyOverallResult, PolicyResult, PolicySummary};
    use chrono::Utc;

    fn failed_compliance_report() -> ComplianceReport {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test".to_string(),
            version: "1".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        };
        let mut report = ComplianceReport::new(&framework, "example.com:443".to_string());
        report.overall_status = ComplianceStatus::Fail;
        report
    }

    fn failed_policy_result() -> PolicyResult {
        PolicyResult {
            policy_name: "test".to_string(),
            policy_version: "1".to_string(),
            target: "example.com:443".to_string(),
            evaluation_time: Utc::now(),
            violations: vec![PolicyViolation::new(
                "protocols.prohibited",
                "Prohibited protocol",
                PolicyAction::Fail,
                "TLS 1.0 is prohibited",
            )],
            exceptions_applied: Vec::new(),
            summary: PolicySummary {
                total_checks: 1,
                passed: 0,
                failed: 1,
                warnings: 0,
                info: 0,
                overall_result: PolicyOverallResult::Fail,
            },
        }
    }

    #[test]
    fn empty_post_processing_and_notice_views_hide_optional_sections() {
        let processing = ScanPostProcessingView {
            compliance_report: None,
            policy_result: None,
            stored_scan_id: None,
            should_fail_exit: false,
        };
        assert!(!processing.should_render_compliance_section());
        assert!(!processing.has_compliance_report());
        assert!(processing.compliance_report().is_none());
        assert!(!processing.should_render_policy_section());
        assert!(!processing.has_policy_result());
        assert!(processing.policy_result().is_none());
        assert!(processing.stored_scan_id().is_none());
        assert!(!processing.has_stored_scan());
        assert!(!processing.should_fail_exit());
        assert!(!processing.should_render_any_section());
        assert!(!processing.should_render_storage_notice());

        let post = ScanPostView {
            post_processing: &processing,
        };
        assert!(!post.should_render());
        assert!(!post.compliance_failed());
        assert!(!post.policy_failed());
        assert!(!post.has_failures());
        assert!(!post.should_fail_exit());
        assert!(!post.should_return_failure_exit());
        assert!(!post.should_render_policy_failure_notice());
        assert!(!post.should_render_compliance_section());
        assert!(post.compliance_report().is_none());
        assert!(!post.should_render_policy_section());
        assert!(post.policy_result().is_none());

        let notice = ScanNoticeView {
            stored_scan_id: None,
        };
        assert!(!notice.has_stored_scan());
        assert!(!notice.should_render_any_notice());
        assert!(notice.stored_scan_id().is_none());
        assert!(notice.stored_scan_id_for_notice().is_none());
        assert!(!notice.should_render_storage_notice_for(Some(7)));
        assert!(!notice.should_render_export_spacing_for(true));
        assert!(!notice.should_render_storage_notice());
    }

    #[test]
    fn failures_and_storage_state_render_their_sections_and_notices() {
        let compliance = failed_compliance_report();
        let policy = failed_policy_result();
        let processing = ScanPostProcessingView {
            compliance_report: Some(&compliance),
            policy_result: Some(&policy),
            stored_scan_id: Some(7),
            should_fail_exit: true,
        };

        assert!(processing.should_render_compliance_section());
        assert!(processing.has_compliance_report());
        assert!(processing.compliance_report().is_some());
        assert!(processing.should_render_policy_section());
        assert!(processing.has_policy_result());
        assert!(processing.policy_result().is_some());
        assert_eq!(processing.stored_scan_id(), Some(7));
        assert!(processing.has_stored_scan());
        assert!(processing.should_fail_exit());
        assert!(processing.should_render_any_section());
        assert!(processing.should_render_storage_notice());

        let post = ScanPostView {
            post_processing: &processing,
        };
        assert!(post.should_render());
        assert!(post.compliance_failed());
        assert!(post.policy_failed());
        assert!(post.has_failures());
        assert!(post.should_fail_exit());
        assert!(post.should_return_failure_exit());
        assert!(post.should_render_policy_failure_notice());
        assert!(post.should_render_compliance_section());
        assert!(post.compliance_report().is_some());
        assert!(post.should_render_policy_section());
        assert!(post.policy_result().is_some());

        let notice = ScanNoticeView {
            stored_scan_id: Some(7),
        };
        assert!(notice.has_stored_scan());
        assert!(notice.should_render_any_notice());
        assert_eq!(notice.stored_scan_id(), Some(7));
        assert_eq!(notice.stored_scan_id_for_notice(), Some(7));
        assert!(notice.should_render_storage_notice_for(Some(7)));
        assert!(notice.should_render_export_spacing_for(true));
        assert!(notice.should_render_storage_notice());
    }
}
